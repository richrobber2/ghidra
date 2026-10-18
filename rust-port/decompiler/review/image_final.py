#!/usr/bin/env python3
"""Read-only final receipt audit for the bounded Rust image-memory extension.

Run only in an exclusive heavy-work slot. No code is built or executed: this
rehashes retained inputs/artifacts, checks complete command receipts, and checks
original checkout/archive preservation. The sole write is a new JSON report.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
RESULTS = ROOT / "results"
CLI_SHA = "bd86a9af949b1c17231291cf5a856643afc3c99f2dbe06c11b9e8c3c432053fe"
ENGINE_SHA = "876c28d48c07126e5db94946c10719eeb96b057c9271daa0114df34e598f262a"
COMMIT = "9a723ce99952771b8368329503aa589ae233e916"
ARCHIVES = {
    "decompiler-native-first-01.tar": "cc448460fcb2d522140084650aaf793fd1c5394f183b371a327eca7f586675da",
    "program-headers-final-01.tar": "7abcf236db29683b57a4f3248753995aee8c4b87b81671da228c088ce652403b",
}
EXPECTED = {
    "image-memory-03": {"semantic_match": 32, "guarded_as_required": 20},
    "image-edges-02": {"semantic_match": 9, "guard_rejected": 8, "guard_aborted": 9},
    "image-runtime-01": {"matched": 15, "guard_aborted": 29},
    "image-zlib-numeric-01": {"semantic_match": 3},
    "image-regression-c-01": {"semantic_match": 42, "rejected_as_required": 18},
    "image-regression-isa-01": {"semantic_match": 17, "guard_aborted": 7},
    "image-regression-rust-02": {"semantic_match": 4},
    "image-regression-zlib-01": {"semantic_match": 2, "rejected_as_required": 1},
    "image-batch-01": {"semantic_match": 4},
}
NUMERIC = {"compressBound", "zlibCompileFlags", "crc32_combine64", "crc32_combine_gen64", "crc32_combine_op"}
POINTERS = {"zlibVersion", "get_crc_table"}


class Audit:
    def __init__(self) -> None:
        self.errors: list[dict] = []
        self.hashes: dict[str, dict] = {}
        self.hash_records = 0
        self.suites: dict[str, dict] = {}
        self.reports: dict[str, dict] = {}

    def error(self, stage: str, message: str, **details) -> None:
        self.errors.append({"stage": stage, "error": message, **details})

    def require(self, condition: bool, stage: str, message: str, **details) -> None:
        if not condition:
            self.error(stage, message, **details)

    def load(self, path: Path):
        return json.loads(path.read_text())

    def digest(self, path: Path) -> dict:
        # All accepted artifacts are frozen while this exclusive audit runs.
        key = str(path.absolute())
        if key not in self.hashes:
            digest = hashlib.sha256()
            count = 0
            with path.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
                    count += len(block)
            self.hashes[key] = {"path": key, "bytes": count, "sha256": digest.hexdigest()}
        return self.hashes[key]

    def check_hash(self, record: dict, stage: str, base: Path = ROOT) -> None:
        self.hash_records += 1
        try:
            path = Path(record["path"])
            if not path.is_absolute():
                path = base / path
            actual = self.digest(path)
            self.require(actual["sha256"] == record["sha256"], stage, "SHA256 mismatch",
                         path=str(path), expected=record["sha256"], actual=actual["sha256"])
            if "bytes" in record:
                self.require(actual["bytes"] == record["bytes"], stage, "byte-count mismatch", path=str(path))
        except Exception as exc:
            self.error(stage, str(exc), record=record)

    def walk(self, value):
        if isinstance(value, dict):
            yield value
            for nested in value.values():
                yield from self.walk(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from self.walk(nested)

    def hash_records_in(self, payload, stage: str, base: Path = ROOT) -> None:
        for record in self.walk(payload):
            if "path" in record and "sha256" in record:
                self.check_hash(record, stage, base)

    def guarded(self, stage: str, operation) -> None:
        try:
            operation()
        except Exception as exc:
            self.error(stage, str(exc), exception=type(exc).__name__)

    def build(self) -> None:
        stage = "source_build"
        directory = RESULTS / "image-build-04"
        build = self.load(directory / "sources.json")
        self.require(build.get("status") == "passed" and build.get("release_unit_tests") == 34,
                     stage, "final build must pass 34 release units")
        self.require("34 passed; 0 failed" in (directory / "tests.log").read_text(),
                     stage, "test log does not confirm all 34 release units")
        sources = build["sources"]
        self.require(isinstance(sources, list) and bool(sources), stage, "source inventory is empty")
        self.hash_records_in(build, stage)
        for record in sources:
            frozen = dict(record, path=str(directory / "source-snapshot" / record["path"]))
            self.check_hash(frozen, stage)
        self.require(build["cli"]["sha256"] == CLI_SHA, stage, "unexpected accepted CLI hash")
        self.check_hash({"path": str(ROOT / "target/release/rust-ghidra"), "sha256": CLI_SHA}, stage)
        self.reports[stage] = {"status": build.get("status"), "release_unit_tests": 34,
                               "source_files": len(sources), "cli_sha256": CLI_SHA,
                               "receipt": self.digest(directory / "sources.json")}

    def suite(self, name: str, expected: dict) -> None:
        stage = name
        directory = RESULTS / name
        result = self.load(directory / "results.json")
        provenance = self.load(directory / "provenance.json")
        self.suites[name] = result
        self.require(result.get("status") == "passed", stage, "accepted suite did not pass")
        # The retained ISA driver predates the top-level errors field. Its
        # complete exact case/status and command gates below are authoritative;
        # every newer driver must carry an explicit empty errors array.
        legacy_isa = name == "image-regression-isa-01" and "errors" not in result
        self.require(legacy_isa or result.get("errors") == [], stage,
                     "accepted suite contains errors", errors=result.get("errors"))
        actual = dict(Counter(case.get("status") for case in result["cases"]))
        self.require(actual == expected and result.get("counts") == expected, stage,
                     "case counts differ from declared gate", expected=expected, actual=actual)
        for case in result["cases"]:
            self.require(case.get("mismatch_count", 0) == 0, stage, "case records semantic mismatches", case=case)
            if case.get("status") == "matched":
                self.require(case.get("actual") == case.get("expected"), stage, "direct runtime result mismatch", case=case)
        events = [json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()]
        self.require(result.get("commands") == len(events), stage, "command/event counts differ",
                     commands=result.get("commands"), events=len(events))
        self.require(bool(events), stage, "suite contains no command receipts")
        identities = set()
        for index, event in enumerate(events):
            self.require(event.get("timed_out") is False and not event.get("launch_error")
                         and type(event.get("returncode")) is int,
                         stage, "incomplete, timed out or failed launch receipt", index=index, event=event)
            self.require(isinstance(event.get("argv"), list) and bool(event["argv"])
                         and isinstance(event.get("elapsed_seconds"), (int, float)),
                         stage, "command receipt lacks argv/timing", index=index)
            for key in ("stdout", "stderr"):
                self.require(isinstance(event.get(key), str) and Path(event[key]).is_file(),
                             stage, "command log missing", index=index, stream=key)
            identities.add(json.dumps(event, sort_keys=True))
        self.require(len(identities) == len(events), stage, "duplicate command receipts")
        for command in self.walk(result):
            if "argv" in command and "returncode" in command:
                self.require(json.dumps(command, sort_keys=True) in identities, stage,
                             "embedded command has no exact event receipt", command=command)
        self.hash_records_in(provenance, stage)
        self.hash_records_in(result, stage)
        if name != "image-runtime-01":
            self.check_hash({"path": str(directory / "candidate/rust-ghidra"), "sha256": CLI_SHA}, stage)
        else:
            self.check_hash({"path": str(directory / "source-snapshot/src/runtime.h"),
                             "sha256": self.digest(ROOT / "src/runtime.h")["sha256"]}, stage)
        self.reports[name] = {"status": result.get("status"), "counts": actual,
            "commands": len(events), "explicit_errors_field": "errors" in result,
            "result": self.digest(directory / "results.json"),
            "provenance": self.digest(directory / "provenance.json"),
            "events": self.digest(directory / "events.jsonl")}

    def coverage(self) -> None:
        stage = "frozen_zlib_coverage"
        directory = RESULTS / "image-memory-03"
        frozen = self.load(directory / "source-snapshot/frozen-zlib-batch.json")
        def body_map(manifest):
            return sorted((row["function"]["address"], row["function"]["size"], row["function"]["file_offset"])
                          for row in manifest["functions"])
        historical = body_map(frozen)
        self.require(len(historical) == len(set(historical)) == 88, stage, "historical map must contain 88 distinct extents")
        bodies, names = set(), set()
        for kind, required in (("u64", NUMERIC), ("pointer", POINTERS)):
            manifest = self.load(directory / f"decompilations/zlib-batch-{kind}/manifest.json")
            accepted = [row for row in manifest["functions"] if row.get("status") == "ok"]
            rejected = [row for row in manifest["functions"] if row.get("status") == "unsupported"]
            found = {row["function"]["name"] for row in accepted}
            self.require(body_map(manifest) == historical and manifest.get("status") == "partial"
                         and manifest.get("backend") == "native-rust" and manifest.get("guarded") is True
                         and manifest.get("truncated") is False and manifest.get("return_kind") == kind
                         and manifest.get("function_count") == manifest.get("attempted_count") == 88
                         and manifest.get("decompiled_count") == len(accepted) == len(required)
                         and manifest.get("unsupported_count") == len(rejected) == 88 - len(required)
                         and len(accepted) + len(rejected) == 88 and found == required,
                         stage, "batch contract or accepted names changed", return_kind=kind, names=sorted(found))
            for row in rejected:
                self.require(isinstance(row.get("error"), str) and bool(row["error"]), stage,
                             "unsupported function lost its diagnostic", function=row.get("function"))
            for row in accepted:
                f = row["function"]
                bodies.add((f["address"], f["size"], f["file_offset"]))
                names.add(f["name"])
                self.require(isinstance(row.get("generated_function"), str) and row["generated_function"].isidentifier(),
                             stage, "accepted artifact has invalid generated function name", function=f)
        self.require(len(bodies) == len(names) == 7, stage, "numeric/pointer union is not seven distinct functions")
        contracts = {
            "compressBound": ("image-regression-zlib-01", 523, None),
            "zlibCompileFlags": ("image-regression-zlib-01", 523, None),
            "crc32_combine64": ("image-zlib-numeric-01", 361, None),
            "crc32_combine_gen64": ("image-zlib-numeric-01", 37, None),
            "crc32_combine_op": ("image-zlib-numeric-01", 731, None),
            "zlibVersion": ("image-memory-03", 1035, 6),
            "get_crc_table": ("image-memory-03", 1035, 64),
        }
        validation = {}
        for name, (suite, count, width) in contracts.items():
            cases = [case for case in self.suites[suite]["cases"]
                     if case.get("function") == name and case.get("status") == "semantic_match"]
            self.require(len(cases) == 1, stage, "real function lacks one accepted execution case", function=name)
            if len(cases) != 1:
                continue
            case = cases[0]
            self.require(case.get("comparisons_per_arm") == count and case.get("mismatch_count") == 0,
                         stage, "execution vector count or mismatches changed", function=name)
            if width is not None:
                self.require(case.get("return_kind") == "pointer" and case.get("read_bytes") == width,
                             stage, "pointer contents contract changed", function=name)
            validation[name] = {"suite": suite, "comparisons_per_arm": count, "read_bytes": width,
                "domain": "native contents, version constant or independent CRC polynomial prefix" if width else
                          "nonnegative signed-64 generator lengths/valid generated CRC operators" if name.startswith("crc32_") else
                          "six-u64 register model; compressBound formula or native flags equivalence"}
        for key in ("standalone", "output_reuse", "explicit_limit"):
            self.require(self.suites["image-batch-01"].get(key, {}).get("status") == "passed",
                         stage, "batch integration control failed", control=key)
        self.reports[stage] = {"inventory": 88, "numeric_artifacts": 5, "pointer_artifacts": 2,
                               "distinct_functions": 7, "execution_validation": validation,
                               "interpretation": "Bounded guarded artifacts and selected-domain execution evidence; not whole-library support."}

    def archives(self) -> None:
        stage = "prior_archives"
        reports = {}
        for name, expected_sha in ARCHIVES.items():
            archive = ROOT.parent / "artifacts" / name
            manifest = self.load(Path(str(archive) + ".json"))
            self.check_hash({"path": str(archive), "sha256": expected_sha,
                             "bytes": manifest["archive_bytes"]}, stage)
            self.require(manifest.get("complete") is True and manifest.get("sha256") == expected_sha
                         and len(manifest["files"]) == manifest.get("file_count"), stage,
                         "archive manifest is incomplete or contradicts expected SHA", archive=name)
            seen, old_results, dependencies = set(), 0, 0
            for record in manifest["files"]:
                path = record["path"]
                self.require(path not in seen, stage, "duplicate archive path", archive=name, path=path)
                seen.add(path)
                old = path.startswith("ghidra-rust-port/decompiler/results/")
                dependency = (path in {"ghidra-rust-port/Cargo.toml", "ghidra-rust-port/Cargo.lock",
                                      "ghidra-rust-port/program-headers/Cargo.toml", "ghidra-rust-port/program-headers/Cargo.lock"}
                              or path.startswith("ghidra-rust-port/src/")
                              or path.startswith("ghidra-rust-port/program-headers/src/"))
                if old or dependency:
                    self.check_hash(record, stage, WORKSPACE)
                    old_results += old
                    dependencies += dependency
            self.require(dependencies > 0, stage, "archive contains no dependency source checks", archive=name)
            if name.startswith("decompiler"):
                self.require(old_results > 0, stage, "baseline archive contains no prior result checks")
            reports[name] = {"sha256": expected_sha, "old_result_files_revalidated": old_results,
                             "dependency_sources_revalidated": dependencies,
                             "excluded_from_unchanged_claim": "Current component sources/docs and workspace AGENTS may intentionally change; archived results do not."}
        self.reports[stage] = reports

    def original_ghidra(self) -> None:
        stage = "original_ghidra"
        checkout = WORKSPACE / "ghidra"
        commands = []
        for args in (["rev-parse", "HEAD"], ["status", "--porcelain=v1", "--untracked-files=normal"]):
            argv = ["git", "-C", str(checkout), *args]
            process = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            commands.append({"argv": argv, "returncode": process.returncode,
                             "stdout": process.stdout, "stderr": process.stderr})
            self.require(process.returncode == 0, stage, "git inspection failed", command=commands[-1])
        self.require(commands[0]["stdout"].strip() == COMMIT, stage, "original checkout commit changed")
        self.require(commands[1]["stdout"] == "", stage, "original checkout is not clean", status=commands[1]["stdout"])
        engine = checkout / "Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile"
        self.check_hash({"path": str(engine), "sha256": ENGINE_SHA}, stage)
        self.reports[stage] = {"commit": commands[0]["stdout"].strip(), "clean": commands[1]["stdout"] == "",
                               "engine": self.digest(engine), "commands": commands}

    def historical_failures(self) -> None:
        stage = "historical_attempts"
        reports = {}
        expected_statuses = {"image-memory-01": "failed", "image-memory-02": "failed",
                             "image-edges-01": "passed", "image-regression-rust-01": "failed"}
        for name, expected_status in expected_statuses.items():
            path = RESULTS / name / "results.json"
            result = self.load(path)
            self.require(result.get("status") == expected_status, stage,
                         "historical attempt missing or relabeled", attempt=name, expected_status=expected_status)
            reports[name] = {"status": result.get("status"), "counts": result.get("counts"),
                             "result": self.digest(path), "events": self.digest(path.parent / "events.jsonl"),
                             "note": "Superseded earlier gate, not a final-candidate acceptance receipt."}
        self.reports[stage] = reports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new JSON report path")
    args = parser.parse_args()
    destination = Path(args.output).absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x") as stream:
        audit = Audit()
        audit.guarded("source_build", audit.build)
        for name, expected in EXPECTED.items():
            audit.guarded(name, lambda name=name, expected=expected: audit.suite(name, expected))
        audit.guarded("frozen_zlib_coverage", audit.coverage)
        audit.guarded("prior_archives", audit.archives)
        audit.guarded("original_ghidra", audit.original_ghidra)
        audit.guarded("historical_attempts", audit.historical_failures)
        report = {"schema": 1, "status": "passed" if not audit.errors else "failed",
                  "complete": not audit.errors, "cli_sha256": CLI_SHA,
                  "scope": "Read-only receipt, provenance, guarded-domain execution and preservation audit; no speed or complete-replica claim.",
                  "checks": audit.reports, "hash_records_checked": audit.hash_records,
                  "distinct_files_hashed": len(audit.hashes), "errors": audit.errors,
                  "audit_source": audit.digest(Path(__file__).resolve()),
                  "performance_claim": "None. No equal-work decompiler performance comparison was performed."}
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({key: report[key] for key in ("status", "hash_records_checked", "distinct_files_hashed", "errors")}, indent=2))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
