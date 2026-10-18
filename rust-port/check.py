#!/usr/bin/env python3
"""Build/test Rust and compare its header results with the original Java oracle."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parent
ENV = os.environ.copy()
ENV.setdefault("CARGO_HOME", "/workspace/toolchains/rust/cargo")
ENV.setdefault("RUSTUP_HOME", "/workspace/toolchains/rust/rustup")
ENV["PATH"] = str(Path(ENV["CARGO_HOME"]) / "bin") + os.pathsep + ENV["PATH"]


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, env=ENV, check=True, **kwargs)


def main():
    inventory = json.loads((ROOT / "source-map.json").read_text())
    ghidra = Path("/workspace/ghidra")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ghidra, text=True).strip()
    assert commit == inventory["source_commit"], "Ghidra revision changed: refresh and review the source map"
    for entry in inventory["files"]:
        digest = hashlib.sha256((ghidra / entry["path"]).read_bytes()).hexdigest()
        assert digest == entry["sha256"], f"Ghidra source changed: {entry['path']}"
    run(["python3", "oracle/run.py"], timeout=90)
    run(["cargo", "test", "--offline", "--locked"], timeout=180)
    run(["cargo", "build", "--release", "--offline", "--locked", "--bin", "ghidra-elf"], timeout=180)
    files = sorted((ROOT / "fixtures").glob("*.elf"))
    output = subprocess.run(
        [str(ROOT / "target/release/ghidra-elf"), "--compatible", *map(str, files)],
        cwd=ROOT, env=ENV, text=True, capture_output=True, timeout=30,
    )
    if output.returncode not in (0, 1):
        raise RuntimeError(f"Rust CLI failed ({output.returncode}): {output.stderr}")
    rust = json.loads(output.stdout)
    java = json.loads((ROOT / "results/java-header-baseline.json").read_text())
    expected = {row["file"]: row for row in java}
    actual = {row["file"]: row for row in rust}
    assert len(rust) == len(java) == len(files) == 30, "Unexpected baseline size"
    assert actual.keys() == expected.keys(), "Fixture result names differ"
    fields = (
        "class_bits", "header_little_endian", "declared_little_endian", "type", "machine",
        "version", "entry_hex", "phoff_hex", "shoff_hex", "flags", "ehsize", "phentsize",
        "phnum", "shentsize", "shnum", "shstrndx",
    )
    failures = []
    for name, reference in expected.items():
        candidate = actual[name]
        for field in ("accepted",) + (fields if reference["accepted"] else ()):
            if reference[field] != candidate.get(field):
                failures.append({"file": name, "field": field,
                                 "java": reference[field], "rust": candidate.get(field)})
    result = {
        "scope": "Original ElfHeader constructor: accept/reject and normalized public values",
        "fixtures": len(files), "passed": len(files) - len({f['file'] for f in failures}),
        "failures": failures,
        "notes": "Diagnostic codes and human-readable error prose are separate APIs; they are not compared here.",
    }
    (ROOT / "results/rust-header-baseline.json").write_text(json.dumps(rust, indent=2) + "\n")
    (ROOT / "results/parity.json").write_text(json.dumps(result, indent=2) + "\n")
    if failures:
        raise AssertionError(json.dumps(failures, indent=2))
    assert output.returncode == (1 if any(not row['accepted'] for row in rust) else 0), "CLI exit status mismatch"
    print(f"PASS: {len(files)} Java/Rust header parity cases; Rust unit tests completed")


if __name__ == "__main__":
    main()
