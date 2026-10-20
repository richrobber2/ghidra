#!/usr/bin/env python3
"""Executable image-memory gate: COPY relocations and absolute addresses.

fixtures/image-copy.c is linked three ways, each with R_X86_64_COPY
relocations for libc's optind and stderr: as a PIE, as a position-dependent
executable built with -fpie (RIP-relative table reads), and as a
position-dependent executable built with -fno-pic (absolute table reads such as
`movzbl table(%rdi),%eax`). The gate requires readelf to show the COPY
relocations, and requires the generated C and Rust for the .rodata readers to
match independent results on every vector:

- `lookup` and `mix` mask their indices and match the table formulas.
- `unchecked` does not. Its expected result is the byte the process would read
  at `table + i`, taken from the file's PT_LOAD bytes, or a guard abort when
  that address leaves the table's read-only segment.

`readopt` reads the copied variable and must be rejected. Each call runs in a
forked child so an abort costs one vector. Every command and result stays in
the fresh output directory.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import random
import re
import resource
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MASK = (1 << 64) - 1
TABLE = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3]
LINKS = {"pie": ["-fpie", "-pie"], "no-pie": ["-fpie", "-no-pie"], "no-pic": ["-fno-pic", "-no-pie"]}
READERS = ("lookup", "mix", "unchecked")


def vectors() -> list[tuple[int, int]]:
    values = [0, 1, 15, 16, 17, 255, 0x157, 0x158, 0x1000, 1 << 31, 1 << 63, MASK - 15, MASK]
    rng = random.Random(0xc0b1)
    cases = [(a, b) for a in values for b in values]
    cases += [(rng.randrange(0, 0x400), rng.randrange(0, 0x400)) for _ in range(256)]
    cases += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(128)]
    return cases


def run(command: list[str], log: list) -> subprocess.CompletedProcess:
    result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    log.append({"command": command, "returncode": result.returncode, "stderr": result.stderr[-2000:]})
    return result


def oracle(binary: Path, log: list):
    """Independent expected results, from readelf and the file bytes."""
    symbols = run(["readelf", "-W", "-s", str(binary)], log).stdout
    table = next(int(m[1], 16) for m in re.finditer(r"^\s*\d+:\s+([0-9a-f]+)\s+16\s+OBJECT\s+LOCAL.*\stable$",
                                                       symbols, re.M))
    data = binary.read_bytes()
    segment = None
    for line in run(["readelf", "-W", "-l", str(binary)], log).stdout.splitlines():
        fields = line.split()
        if fields[:1] == ["LOAD"]:
            offset, address, file_size = int(fields[1], 16), int(fields[2], 16), int(fields[4], 16)
            if address <= table < address + file_size:
                segment = (offset, address, file_size)
    offset, address, file_size = segment

    def unchecked(a: int, b: int) -> str:
        target = (table + a) & MASK
        if address <= target < address + file_size:
            return str(data[offset + target - address])
        return "abort"

    return {"lookup": lambda a, b: str(TABLE[a & 15]),
            "mix": lambda a, b: str(TABLE[a & 15] * 256 + TABLE[b & 15]),
            "unchecked": unchecked}


def call(function, a: int, b: int) -> str:
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
        os.write(write, str(int(function(a, b, 0, 0, 0, 0))).encode())
        os._exit(0)
    os.close(write)
    value = b""
    while chunk := os.read(read, 64):
        value += chunk
    os.close(read)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return "abort" if os.WTERMSIG(status) == signal.SIGABRT else f"signal {os.WTERMSIG(status)}"
    return value.decode() if os.WEXITSTATUS(status) == 0 else f"exit {os.WEXITSTATUS(status)}"


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
        expected = oracle(binary, log)
        directory = output / f"analyze-{link}"
        run([str(args.cli), "analyze", str(binary), "--lang", "both", "--output", str(directory)], log)
        manifest = json.loads((directory / "manifest.json").read_text())
        rows = {row["function"]["name"]: row for row in manifest["functions"]}
        entry["status"] = {name: rows[name]["status"] for name in (*READERS, "readopt") if name in rows}
        if rows.get("readopt", {}).get("status") == "ok":
            failures.append(f"{link}: readopt reads a COPY target and must be rejected")
        if any(rows.get(name, {}).get("status") != "ok" for name in READERS):
            failures.append(f"{link}: the .rodata readers must decompile: {entry['status']}")
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
            for name in READERS:
                function = getattr(library, rows[name]["generated_function"])
                function.argtypes = [ctypes.c_uint64] * 6
                function.restype = ctypes.c_uint64
                results = [(call(function, a, b), expected[name](a, b)) for a, b in cases]
                wrong = [i for i, (got, want) in enumerate(results) if got != want]
                entry[f"{language}_{name}"] = {"wrong": len(wrong),
                                               "aborts": sum(want == "abort" for _, want in results)}
                if wrong:
                    first = wrong[0]
                    failures.append(f"{link}: generated {language} {name} wrong on {len(wrong)} vectors, "
                                    f"first {cases[first]}: {results[first]}")
    report.update(vectors=len(cases), failures=failures, status="failed" if failures else "passed")
    (output / "commands.json").write_text(json.dumps(log, indent=2) + "\n")
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}: {len(cases)} vectors; {json.dumps(report['links'])}; "
          f"{output / 'summary.json'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
