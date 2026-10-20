#!/usr/bin/env python3
"""R_X86_64_COPY gate for the read-only image model.

fixtures/image-copy.c is linked as a PIE and as a position-dependent
executable, each with COPY relocations for libc's optind and stderr. The gate
requires readelf to show the COPY relocations, `lookup` and `mix` (which read
.rodata) to decompile in C and Rust and match independent formulas, and
`readopt` (which reads the copied variable) to be rejected. Every command and
result stays in the fresh output directory.
"""
from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
import random
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MASK = (1 << 64) - 1
TABLE = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3]
EXPECTED = {"lookup": lambda a, b: TABLE[a & 15], "mix": lambda a, b: TABLE[a & 15] * 256 + TABLE[b & 15]}
LINKS = {"pie": ["-fpie", "-pie"], "no-pie": ["-fpie", "-no-pie"]}


def vectors() -> list[tuple[int, int]]:
    values = [0, 1, 15, 16, 255, 1 << 31, 1 << 63, MASK]
    rng = random.Random(0xc0b1)
    return [(a, b) for a in values for b in values] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(256)]


def run(command: list[str], log: list) -> subprocess.CompletedProcess:
    result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    log.append({"command": command, "returncode": result.returncode, "stderr": result.stderr[-2000:]})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new result directory")
    parser.add_argument("--cli", type=Path, required=True, help="rust-ghidra executable")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    log, failures, report = [], [], {"links": {}}
    cases = vectors()
    for link, flags in LINKS.items():
        entry = report["links"][link] = {}
        binary = output / f"image-copy-{link}"
        if run([args.cc, "-O2", *flags, str(ROOT / "fixtures/image-copy.c"), "-o", str(binary)], log).returncode:
            failures.append(f"{link}: compile failed")
            continue
        relocations = run(["readelf", "-W", "-r", str(binary)], log).stdout
        entry["copy_relocations"] = relocations.count("R_X86_64_COPY")
        if entry["copy_relocations"] < 2:
            failures.append(f"{link}: expected COPY relocations for optind and stderr")
        directory = output / f"analyze-{link}"
        run([str(args.cli), "analyze", str(binary), "--lang", "both", "--output", str(directory)], log)
        manifest = json.loads((directory / "manifest.json").read_text())
        rows = {row["function"]["name"]: row for row in manifest["functions"]}
        entry["status"] = {name: rows[name]["status"] for name in ("lookup", "mix", "readopt") if name in rows}
        if rows.get("readopt", {}).get("status") == "ok":
            failures.append(f"{link}: readopt reads a COPY target and must be rejected")
        if any(rows.get(name, {}).get("status") != "ok" for name in EXPECTED):
            failures.append(f"{link}: lookup and mix must decompile: {entry['status']}")
            continue
        libraries = {"c": directory / "c.so", "rust": directory / "rust.so"}
        builds = {"c": [args.cc, "-std=c11", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-stack-protector",
                        str(directory / "decompiled.c"), "-o", str(libraries["c"])],
                  "rust": [args.rustc, "--edition", "2024", "-O", "--crate-type", "cdylib", "-C", "panic=abort",
                           "-D", "warnings", str(directory / "decompiled.rs"), "-o", str(libraries["rust"])]}
        for language, command in builds.items():
            if run(command, log).returncode:
                failures.append(f"{link}: generated {language} does not build")
                continue
            library = ctypes.CDLL(str(libraries[language]))
            for name, formula in EXPECTED.items():
                function = getattr(library, rows[name]["generated_function"])
                function.argtypes = [ctypes.c_uint64] * 6
                function.restype = ctypes.c_uint64
                wrong = sum(function(a, b, 0, 0, 0, 0) != formula(a, b) for a, b in cases)
                entry[f"{language}_{name}_wrong"] = wrong
                if wrong:
                    failures.append(f"{link}: generated {language} {name} wrong on {wrong} vectors")
    report.update(vectors=len(cases), failures=failures, status="failed" if failures else "passed")
    (output / "commands.json").write_text(json.dumps(log, indent=2) + "\n")
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}: {json.dumps(report['links'])}; {output / 'summary.json'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
