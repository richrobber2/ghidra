#!/usr/bin/env python3
"""Integration of accepted combined image-memory C and the standalone Rust CLI.

Consumes the frozen image-memory-03 candidate, input and both accepted batch C
artifacts. This adds combined-translation-unit execution evidence, not new
function coverage or timing evidence. Heavy work must run serially.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

import image_validation
import validate

ROOT = Path(__file__).resolve().parents[1]
ACCEPTED = ROOT / "results/image-memory-03"
MASK = (1 << 64) - 1
TARGETS = {"u64": ("compressBound", "zlibCompileFlags"),
           "pointer": ("zlibVersion", "get_crc_table")}


def freeze(source: Path, target: Path, provenance: dict) -> None:
    before = validate.digest(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    after = validate.digest(target)
    if before["sha256"] != after["sha256"]:
        raise RuntimeError(f"source changed during snapshot: {source}")
    provenance["sources"].append({"original": before, "frozen": after})


def wrapping_bound(values: list[int]) -> int:
    length = values[0]
    return (length + (length >> 12) + (length >> 14) + (length >> 25) + 13) & MASK


def verify_batch(manifest: dict, kind: str, frozen_map: list[tuple], expected_count: int) -> dict:
    rows = manifest["functions"]
    accepted = [row for row in rows if row.get("status") == "ok"]
    rejected = [row for row in rows if row.get("status") == "unsupported"]
    if (manifest.get("status") != "partial" or manifest.get("backend") != "native-rust"
            or manifest.get("return_kind") != kind or manifest.get("guarded") is not True
            or manifest.get("truncated") is not False or manifest.get("function_count") != 88
            or manifest.get("attempted_count") != 88 or image_validation.body_map(manifest) != frozen_map
            or len(accepted) != expected_count or len(rejected) + len(accepted) != 88
            or manifest.get("decompiled_count") != len(accepted)
            or manifest.get("unsupported_count") != len(rejected)):
        raise ValueError(f"accepted {kind} batch no longer matches its complete 88-body contract")
    named = {row["function"]["name"]: row for row in accepted}
    for name in TARGETS[kind]:
        if name not in named or not isinstance(named[name].get("generated_function"), str):
            raise ValueError(f"accepted {kind} batch lacks required generated function {name}")
        if not named[name]["generated_function"].isidentifier():
            raise ValueError("generated function name must be a C identifier")
    return named


def positive(commands: validate.Commands, script: Path, numeric_worker: Path, original: Path,
             generated: Path, name: str, emitted_name: str, kind: str, vectors: list,
             output: Path, cases: list) -> None:
    width = 6 if name == "zlibVersion" else 64 if name == "get_crc_table" else 0
    case = {"function": name, "return_kind": kind, "status": "running",
            "generated_function": emitted_name, "combined_library": str(generated)}
    cases.append(case)
    observed = {}
    for arm, library, function in (("native", original, name), ("combined_generated", generated, emitted_name)):
        worker = script if kind == "pointer" else numeric_worker
        command = commands.run(f"execute-{name}-{arm}", [sys.executable, str(worker), "--worker"], timeout=5,
            payload={"library": str(library), "function": function, "inputs": vectors,
                     "return_kind": kind, "read_bytes": width})
        case[f"{arm}_command"] = command
        try:
            observed[arm] = image_validation.require_outputs(command, len(vectors), kind == "pointer", width)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            case.update(status="execution_failed", error=str(exc), arm=arm)
    if len(observed) != 2:
        return
    if name == "compressBound":
        expected = [wrapping_bound(values) for values in vectors]
        oracle = "native execution plus independent wrapping bound formula"
    elif name == "zlibCompileFlags":
        expected = observed["native"]
        oracle = "native-library equivalence only"
    else:
        contents = b"1.3.1\0" if name == "zlibVersion" else image_validation.crc_prefix()
        expected = [contents.hex()] * len(vectors)
        oracle = "native contents plus independent version/CRC polynomial expectation"
    mismatches = [{"arm": arm, "input": vectors[index], "expected": wanted, "actual": actual}
        for arm, values in observed.items() for index, (wanted, actual) in enumerate(zip(expected, values))
        if wanted != actual]
    case["mismatch_count"] = len(mismatches)
    if mismatches:
        path = output / "generated" / f"{name}-mismatches.json"
        path.write_text(json.dumps(mismatches, indent=2) + "\n")
        case.update(status="semantic_mismatch", mismatches=str(path))
    else:
        case.update(status="semantic_match", comparisons_per_arm=len(vectors), oracle=oracle,
                    read_bytes=width if kind == "pointer" else None)


def isolated_cli(commands: validate.Commands, cli: Path, library: Path, output: Path,
                 summary: dict) -> None:
    directory = output / "standalone"
    argv = ["/usr/bin/env", "PATH=/nonexistent-rust-ghidra-path",
        "JAVA_HOME=/nonexistent-rust-ghidra-java", "GHIDRA_HOME=/nonexistent-rust-ghidra-ghidra",
        str(cli), "decompile", str(library), "--function", "zlibVersion", "--return", "pointer",
        "--output", str(directory)]
    command = commands.run("standalone-without-java-or-path", argv)
    manifest = json.loads((directory / "manifest.json").read_text())
    if (not validate.successful(command) or manifest.get("status") != "ok"
            or manifest.get("backend") != "native-rust" or manifest.get("return_kind") != "pointer"
            or manifest.get("guarded") is not True
            or not validate.generated_source(manifest, directory).is_file()
            or not isinstance(manifest.get("image_objects"), list) or not manifest["image_objects"]):
        raise ValueError("direct native CLI did not decompile an image pointer with missing PATH/Java/Ghidra")
    before = [validate.digest(path) for path in sorted(directory.rglob("*")) if path.is_file()]
    reuse = commands.run("standalone-output-reuse", argv)
    after = [validate.digest(path) for path in sorted(directory.rglob("*")) if path.is_file()]
    if reuse["timed_out"] or reuse.get("returncode") != 2 or before != after:
        raise ValueError("existing output must reject with exit2 and preserve every existing artifact")
    summary["standalone"] = {"status": "passed", "command": command,
        "environment": {"PATH": "/nonexistent-rust-ghidra-path", "JAVA_HOME": "/nonexistent-rust-ghidra-java",
                        "GHIDRA_HOME": "/nonexistent-rust-ghidra-ghidra"},
        "interpretation": "absolute native executable invoked directly through env; no external runtime tool lookup succeeds"}
    summary["output_reuse"] = {"status": "passed", "command": reuse,
        "expected_returncode": 2, "artifacts_unchanged": before}


def bounded_cli(commands: validate.Commands, cli: Path, library: Path, output: Path,
                frozen_map: list[tuple], summary: dict) -> None:
    directory = output / "limited-batch"
    command = commands.run("explicit-one-function-limit", [str(cli), "analyze", str(library),
        "--return", "u64", "--max-functions", "1", "--output", str(directory)])
    manifest = json.loads((directory / "manifest.json").read_text())
    rows = manifest["functions"]
    if (command["timed_out"] or command.get("returncode") != 1 or manifest.get("status") != "partial"
            or manifest.get("backend") != "native-rust" or manifest.get("return_kind") != "u64"
            or manifest.get("truncated") is not True or manifest.get("function_count") != 88
            or manifest.get("attempted_count") != 1 or len(rows) != 1
            or image_validation.body_map(manifest) != frozen_map[:1]
            or any(row.get("status") not in {"ok", "unsupported"} for row in rows)
            or manifest.get("decompiled_count") + manifest.get("unsupported_count") != 1):
        raise ValueError("explicit function limit must preserve 88-body denominator and report partial/truncated")
    summary["explicit_limit"] = {"status": "passed", "command": command,
        "manifest": str(directory / "manifest.json"), "frozen_denominator": 88,
        "attempted_count": 1, "truncated": True}


def run(args: argparse.Namespace) -> int:
    output, cli = Path(args.output).resolve(), Path(args.cli).resolve()
    accepted_cli = ACCEPTED / "candidate/rust-ghidra"
    if not all(path.is_file() for path in (cli, accepted_cli, ACCEPTED / "results.json")):
        raise SystemExit("candidate and accepted image-memory-03 inputs are required")
    if validate.digest(cli)["sha256"] != validate.digest(accepted_cli)["sha256"]:
        raise SystemExit("CLI differs from the accepted image-memory-03 candidate")
    accepted_results = json.loads((ACCEPTED / "results.json").read_text())
    if accepted_results.get("status") != "passed":
        raise SystemExit("image-memory-03 must remain passed")
    output.mkdir(parents=True, exist_ok=False)
    for name in ("logs", "candidate", "input", "source-snapshot", "generated"):
        (output / name).mkdir()
    provenance = {"sources": [], "python": validate.digest(Path(sys.executable).resolve()),
                  "accepted_result": validate.digest(ACCEPTED / "results.json")}
    frozen_cli, library = output / "candidate/rust-ghidra", output / "input/libz.so.1.3.1"
    sources = [(cli, frozen_cli), (ACCEPTED / "input/libz.so.1.3.1", library),
        (Path(__file__).resolve(), output / "source-snapshot/review/image_batch.py"),
        (ROOT / "review/image_validation.py", output / "source-snapshot/review/image_validation.py"),
        (ROOT / "review/validate.py", output / "source-snapshot/review/validate.py"),
        (ACCEPTED / "source-snapshot/fixtures/corpus.json", output / "source-snapshot/fixtures/corpus.json"),
        (ACCEPTED / "source-snapshot/frozen-zlib-batch.json", output / "source-snapshot/frozen-zlib-batch.json")]
    for kind in ("u64", "pointer"):
        directory = ACCEPTED / "decompilations" / f"zlib-batch-{kind}"
        sources.extend((directory / name, output / "source-snapshot" / kind / name)
                       for name in ("manifest.json", "decompiled.c"))
    for source, target in sources:
        freeze(source, target, provenance)
    commands = validate.Commands(output)
    cases, errors = [], []
    summary = {"schema": 1, "status": "running", "cases": cases, "errors": errors,
        "scope": "combined accepted image-memory C, explicit CLI modes and agent integration; no new coverage or speed claim"}
    config = json.loads((output / "source-snapshot/fixtures/corpus.json").read_text())
    vectors = validate.inputs(config)
    (output / "inputs.json").write_text(json.dumps(vectors) + "\n")
    summary["input_vectors"] = len(vectors)
    expected_map = image_validation.body_map(json.loads((output / "source-snapshot/frozen-zlib-batch.json").read_text()))
    try:
        if len(expected_map) != 88 or len(set(expected_map)) != 88:
            raise ValueError("frozen historical map must retain 88 distinct bodies")
        commands.run("compiler-version", [args.cc, "--version"])
        summaries = {}
        for kind, count in (("u64", 5), ("pointer", 2)):
            manifest = json.loads((output / "source-snapshot" / kind / "manifest.json").read_text())
            named = verify_batch(manifest, kind, expected_map, count)
            source = output / "source-snapshot" / kind / "decompiled.c"
            generated = output / "generated" / f"combined-{kind}.so"
            command = commands.run(f"compile-combined-{kind}", [args.cc, "-O2", *image_validation.CFLAGS,
                "-Werror=implicit-function-declaration", "-Werror=return-type", "-Werror=shift-count-negative",
                "-Werror=shift-count-overflow", str(source), "-o", str(generated)])
            summaries[kind] = {"compile_command": command, "artifact_count": count,
                              "input_manifest": str(output / "source-snapshot" / kind / "manifest.json")}
            if not validate.successful(command):
                errors.append({"stage": "compile_combined", "return_kind": kind, "command": command})
                continue
            for name in TARGETS[kind]:
                positive(commands, output / "source-snapshot/review/image_validation.py",
                    output / "source-snapshot/review/validate.py", library, generated, name,
                    named[name]["generated_function"], kind, vectors, output, cases)
        summary["combined_batches"] = summaries
        isolated_cli(commands, frozen_cli, library, output, summary)
        bounded_cli(commands, frozen_cli, library, output, expected_map, summary)
    except Exception as exc:
        errors.append({"stage": "runner", "type": type(exc).__name__, "error": str(exc)})
    for row in provenance["sources"]:
        for key in ("original", "frozen"):
            after = validate.digest(Path(row[key]["path"]))
            row[f"{key}_after"] = after
            if row[key] != after:
                errors.append({"stage": "provenance", "error": f"source changed: {row[key]['path']}"})
    if provenance["accepted_result"] != validate.digest(ACCEPTED / "results.json"):
        errors.append({"stage": "provenance", "error": "accepted source summary changed"})
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    counts = {}
    for case in cases: counts[case["status"]] = counts.get(case["status"], 0) + 1
    summary["counts"], summary["commands"] = counts, commands.count
    summary["artifacts"] = [validate.digest(path) for path in sorted((output / "generated").glob("*.so"))]
    summary["status"] = "passed" if (not errors and counts.get("semantic_match", 0) == 4
        and all(summary.get(key, {}).get("status") == "passed"
                for key in ("standalone", "output_reuse", "explicit_limit"))) else "failed"
    (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({key: summary.get(key) for key in ("status", "input_vectors", "counts", "errors")}, indent=2))
    return 0 if summary["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--output", required=True, help="fresh result directory")
    parser.add_argument("--cc", default="gcc")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
