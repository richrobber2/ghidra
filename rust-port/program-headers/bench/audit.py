#!/usr/bin/env python3
"""Read-only benchmark receipt audit; does not rebuild or time anything."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from localenv import resolve, snapshot_path  # noqa: E402

MASK64 = (1 << 64) - 1
PROTOCOL = {"processes": 3, "warmup_ms": 10_000, "sample_ms": 500, "samples": 5}
SMOKE = {"processes": 1, "warmup_ms": 100, "sample_ms": 50, "samples": 2}


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def require(condition: bool, description: str) -> None:
    if not condition:
        raise ValueError(description)


def audit(directory: Path, external: bool) -> dict:
    results = json.loads((directory / "results.json").read_text())
    require(results["status"] == "passed", "run is not passed")
    mode = results["mode"]
    require(mode in ("fixed-production", "smoke", "preflight"), "unknown mode")
    protocol = results["protocol"]
    require(protocol == (SMOKE if mode == "smoke" else PROTOCOL) or mode == "preflight" and protocol in (SMOKE, PROTOCOL), "protocol changed")
    order = ["java", "rust", "rust", "java", "java", "rust"][:protocol["processes"] * 2]
    require(results["order"] == order, "order changed")
    manifest = json.loads((directory / "corpus-manifest.json").read_text())
    require(manifest == results["corpus"] and len(manifest) == 23, "corpus manifest mismatch")
    for entry in manifest:
        path = directory / entry["path"]
        require(path.stat().st_size == entry["bytes"] and sha256(path) == entry["sha256"], f"corpus bytes changed: {path}")
    for original, expected in results["source_sha256"].items():
        source = resolve(original)
        snapshot = directory / "source-snapshot" / snapshot_path(original)
        require(sha256(snapshot) == expected, f"source snapshot changed: {snapshot}")
        if external:
            require(sha256(source) == expected, f"live source changed: {source}")
    tools = results["toolchains"]
    require(sha256(directory / tools["rust_executable"]) == tools["rust_executable_sha256"], "Rust binary changed")
    require(sha256(directory / "classes/ElfProgramHeadersBench.class") == tools["java_class_sha256"], "Java class changed")
    if external:
        for jar in tools["classpath"]:
            path = Path(jar["path"])
            require(path.stat().st_size == jar["bytes"] and sha256(path) == jar["sha256"], f"classpath changed: {path}")
    events = [json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()]
    starts = [event for event in events if event["event"] == "command_start"]
    ends = [event for event in events if event["event"] == "command_end"]
    require(len(starts) == len(ends) == (7 if mode == "preflight" else 7 + len(order)), "incomplete command lifecycle")
    for start, end in zip(starts, ends, strict=True):
        require(start["label"] == end["label"] and start["command"] == end["command"], "command lifecycle mismatch")
        require(end["returncode"] == 0 and end["timed_out"] is False, "failed/timed-out command")
        require((directory / end["stdout"]).is_file() and (directory / end["stderr"]).is_file(), "command logs missing")
    reference = results["preflight"]["java"]["data"]
    require(len(reference["digests"]) == 23, "wrong preflight digest count")
    require(sum(map(int, reference["digests"])) & MASK64 == int(reference["corpus_checksum"]), "preflight sum mismatch")
    require(results["all_per_input_digests_match"] is True, "digest gate missing")
    observed_order = []
    for name in ("java", "rust"):
        observations = [results["preflight"][name], *results["steady"][name]]
        expected_processes = 0 if mode == "preflight" else protocol["processes"]
        require(len(results["steady"][name]) == expected_processes, "process count mismatch")
        for position, observation in enumerate(observations):
            raw = json.loads((directory / observation["stdout"]).read_text())
            data = observation["data"]
            require(raw["digests"] == reference["digests"] and raw["corpus_checksum"] == reference["corpus_checksum"], "raw digest mismatch")
            require(len(raw["samples"]) == (protocol["samples"] if position else 0), "raw sample count mismatch")
            require(data["digests"] == raw["digests"] and data["corpus_checksum"] == raw["corpus_checksum"], "copied digest mismatch")
            require(len(data["samples"]) == len(raw["samples"]), "copied sample count mismatch")
            for sample, copied in zip(raw["samples"], data["samples"], strict=True):
                require(all(copied[key] == value for key, value in sample.items()), "copied sample changed")
                require(sample["passes"] > 0 and sample["parses"] == sample["passes"] * 23, "pass/parse count mismatch")
                require(int(sample["checksum"]) == (sample["passes"] * int(reference["corpus_checksum"])) & MASK64, "sample checksum mismatch")
                require(sample["elapsed_ns"] >= protocol["sample_ms"] * 1_000_000, "sample too short")
                require(copied["ns_per_header_and_table"] == sample["elapsed_ns"] / sample["parses"], "normalized timing mismatch")
            if position:
                median = statistics.median(sample["elapsed_ns"] / sample["parses"] for sample in raw["samples"])
                require(median == observation["median_ns_per_header_and_table"], "process median mismatch")
                observed_order.append((observation["order_position"], name))
    if mode != "preflight":
        require([name for _, name in sorted(observed_order)] == order, "observed process order mismatch")
        for name in ("java", "rust"):
            medians = [observation["median_ns_per_header_and_table"] for observation in results["steady"][name]]
            summary = results["summary"][name]
            require(summary == {"process_sample_medians_ns": medians, "median_ns": statistics.median(medians),
                                "min_process_median_ns": min(medians), "max_process_median_ns": max(medians)}, "summary changed")
        ratio = results["summary"]["java"]["median_ns"] / results["summary"]["rust"]["median_ns"]
        require(results["summary"]["java_over_rust_ratio_of_process_medians"] == ratio, "ratio mismatch")
    return {"status": "passed", "mode": mode, "corpus_inputs": len(manifest), "complete_commands": len(ends),
            "timed_processes": len(observed_order), "external_sources_and_jars_checked": external}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("--external", action="store_true", help="also hash current source files and original classpath jars")
    args = parser.parse_args()
    print(json.dumps(audit(args.result.resolve(), args.external), indent=2))


if __name__ == "__main__":
    main()
