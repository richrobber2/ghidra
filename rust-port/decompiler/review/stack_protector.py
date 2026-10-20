#!/usr/bin/env python3
"""Stack-protector and aborting-import gate.

fixtures/stack-protector.c is built as a shared object with
-fstack-protector-all at O0, O2 and O3. Every function reads the %fs:0x28
canary and calls __stack_chk_fail through the PLT on a mismatch; `checked` and
`asserted` also abort through abort() and assert(). The gate decompiles each
function in C and Rust and calls the native original, the generated C and the
generated Rust on the same vectors, each call in a forked child. All three
must give the same result or abort on the same vectors, and match the
independent formulas. `prints` calls puts() and must be rejected. Every
command and result stays in the fresh output directory.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import random
import resource
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MASK = (1 << 64) - 1
LEVELS = ["O0", "O2", "O3"]


def local_table(a: int, b: int) -> str:
    return str(((a * (a & 7) + b) ^ (a * (b & 7) + b)) & MASK)


EXPECTED = {
    "local_table": local_table,
    "checked": lambda a, b: "abort" if a == 0xdead else str((a + b) & MASK),
    "asserted": lambda a, b: "abort" if a == 7 else str((a * b) & MASK),
}
REJECT = ["prints"]


def vectors() -> list[tuple[int, int]]:
    values = [0, 1, 7, 8, 0xdead, 0xdeae, 1 << 32, 1 << 63, MASK]
    rng = random.Random(0x5ca1ab1e)
    return [(a, b) for a in values for b in values] + [(rng.getrandbits(64), rng.getrandbits(64))
                                                     for _ in range(128)]


def run(command: list[str], log: list) -> subprocess.CompletedProcess:
    result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    log.append({"command": command, "returncode": result.returncode, "stderr": result.stderr[-2000:]})
    return result


def call(function, a: int, b: int) -> str:
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 2)
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


def bind(library: Path, name: str):
    function = getattr(ctypes.CDLL(str(library)), name)
    function.argtypes = [ctypes.c_uint64] * 6
    function.restype = ctypes.c_uint64
    return function


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new result directory")
    parser.add_argument("--cli", type=Path, required=True, help="rust-ghidra executable")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    log, failures, report = [], [], {"levels": {}}
    cases = vectors()
    for level in LEVELS:
        entry = report["levels"][level] = {}
        original = output / f"stack-protector-{level}.so"
        if run([args.cc, f"-{level}", "-fPIC", "-shared", "-fstack-protector-all",
                str(ROOT / "fixtures/stack-protector.c"), "-o", str(original)], log).returncode:
            failures.append(f"{level}: compile failed")
            continue
        for name in [*EXPECTED, *REJECT]:
            directory = output / f"{level}-{name}"
            run([str(args.cli), "decompile", str(original), "--function", name, "--lang", "both",
                 "--output", str(directory)], log)
            manifest = json.loads((directory / "manifest.json").read_text())
            if name in REJECT:
                entry[name] = manifest["status"]
                if manifest["status"] == "ok":
                    failures.append(f"{level}: {name} calls a returning import and must be rejected")
                continue
            if manifest["status"] != "ok":
                failures.append(f"{level}: {name} must decompile: {manifest.get('error')}")
                continue
            arms = {"original": bind(original, name)}
            for language, source, command in (
                    ("c", "decompiled.c", [args.cc, "-std=c11", "-O2", "-fPIC", "-shared", "-nostdlib",
                                           "-fno-stack-protector"]),
                    ("rust", "decompiled.rs", [args.rustc, "--edition", "2024", "-O", "--crate-type", "cdylib",
                                               "-C", "panic=abort", "-D", "warnings"])):
                library = directory / f"{language}.so"
                if run([*command, str(directory / source), "-o", str(library)], log).returncode:
                    failures.append(f"{level}: generated {language} for {name} does not build")
                    continue
                arms[language] = bind(library, manifest["generated_function"])
            counts = {}
            for arm, function in arms.items():
                results = [call(function, a, b) for a, b in cases]
                wrong = [i for i, result in enumerate(results) if result != EXPECTED[name](*cases[i])]
                counts[arm] = {"wrong": len(wrong), "aborts": results.count("abort")}
                if wrong:
                    failures.append(f"{level}: {arm} {name} wrong on {len(wrong)} vectors, first "
                                    f"{cases[wrong[0]]}: {results[wrong[0]]}")
            entry[name] = counts
    report.update(vectors=len(cases), failures=failures, status="failed" if failures else "passed")
    (output / "commands.json").write_text(json.dumps(log, indent=2) + "\n")
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}: {len(cases)} vectors; {json.dumps(report['levels'])}; "
          f"{output / 'summary.json'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
