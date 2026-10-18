#!/usr/bin/env python3
"""Independent, fixed-corpus semantic gate for the native Rust decompiler.

This runner never changes the corpus in response to candidate failures. It
retains every command, unsupported function, failure, and mismatch. It builds
only its new result directory and executes trusted fixtures/generated code in
short-lived, resource-limited children. It is not a general binary sandbox.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import resource
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
MASK = (1 << 64) - 1
U32 = (1 << 32) - 1


def signed(value: int, width: int) -> int:
    value &= (1 << width) - 1
    return value - (1 << width) if value & (1 << (width - 1)) else value


def expected(name: str, args: list[int]) -> int:
    """Independent integer formulas; all narrowing/wrapping is explicit."""
    a, b, c, d, e, f = args
    if name == "add_mix":
        value = (((a + b) & MASK) ^ ((c + 0x9e3779b97f4a7c15) & MASK)) + (d ^ e) + f
    elif name == "sub_borrow":
        value = a - b - c + int(a < b) + int(d <= e) + f
    elif name == "bit_logic":
        value = ((a & b) | (c ^ d)) ^ ((~e & MASK) & f)
    elif name == "shifts64":
        value = ((a << (b & 63)) & MASK) ^ (c >> (d & 63)) ^ ((e + f) & MASK)
    elif name == "rotate64":
        n = b & 63
        value = (((a << n) & MASK) | (a >> ((-n) & 63))) ^ c ^ d ^ e ^ f
    elif name == "multiply64":
        value = a * b + c * 37 - d * e + f
    elif name == "select_unsigned":
        value = (c if a < b else d) + (a if e >= f else b)
    elif name == "select_signed":
        value = (c if signed(a, 64) < signed(b, 64) else d) ^ (a if signed(e, 64) >= signed(f, 64) else b)
    elif name == "minmax_u32":
        value = ((min(a & U32, b & U32) + max(c & U32, d & U32) + (e & U32)) & U32) ^ f
    elif name == "signed32_branch":
        if signed(a, 32) <= signed(b, 32):
            value = (((a & U32) + (c & U32)) & U32) + d
        else:
            value = (((b & U32) - (e & U32)) & U32) ^ f
    elif name == "loop_accumulate":
        value = b
        for i in range((a & 15) + 1):
            value = ((value ^ ((c + i) & MASK)) + d) & MASK
        value ^= e ^ f
    elif name == "loop_xor":
        value = b
        for n in range((a & 7) + 1, 0, -1):
            value = (((value << 1) & MASK) ^ ((c + n) & MASK) ^ (value >> 3)) & MASK
        value += d + e + f
    elif name == "stack_spill":
        x, y, z = (a + b) & MASK, c ^ d, (e - f) & MASK
        x ^= y
        y = (y + z) & MASK
        value = x + y + z
    elif name == "zero_extend32":
        x = (((a & U32) + (b & U32)) & U32) ^ (c & U32)
        n = d & 31
        x = ((x << n) | (x >> ((-n) & 31))) & U32
        value = x + e - f
    else:
        raise ValueError(f"no independent formula for {name}")
    return value & MASK


def inputs(config: dict) -> list[list[int]]:
    values = [0, 1, 2, 3, 7, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 255,
              (1 << 31) - 1, 1 << 31, (1 << 32) - 1, 1 << 32,
              (1 << 63) - 1, 1 << 63, MASK - 1, MASK]
    cases = [[v] * 6 for v in values]
    base = [0x0123456789abcdef, 0xfedcba9876543210, 0x8000000080000000,
            0x7fffffff7fffffff, MASK, 1]
    for position in range(6):
        for value in values:
            case = base.copy()
            case[position] = value
            cases.append(case)
    for a in values[-8:] + values[:2]:
        for b in values[-8:] + values[:2]:
            cases.append([a, b, MASK, 1 << 63, 1 << 32, 0xaaaaaaaa55555555])
    rng = random.Random(config["input_seed"])
    cases.extend([[rng.getrandbits(64) for _ in range(6)] for _ in range(config["random_input_count"])])
    # Preserve insertion order while avoiding duplicate boundary tuples.
    return [list(case) for case in dict.fromkeys(map(tuple, cases))]


def worker() -> int:
    """Load only a caller-selected fixture library and invoke its one function."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
    payload = json.load(sys.stdin)
    library = ctypes.CDLL(payload["library"])
    function = getattr(library, payload["function"])
    function.argtypes = [ctypes.c_uint64] * 6
    function.restype = ctypes.c_uint64
    outputs = [int(function(*case)) for case in payload["inputs"]]
    json.dump({"outputs": outputs}, sys.stdout)
    return 0


def digest(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class Commands:
    def __init__(self, output: Path):
        self.output = output
        self.events = output / "events.jsonl"
        self.count = 0

    def run(self, label: str, argv: list[str], *, timeout: int = 30, payload: dict | None = None) -> dict:
        self.count += 1
        stem = f"{self.count:03d}-{label}"
        start = time.monotonic()
        record = {"label": label, "argv": argv, "timeout_seconds": timeout,
                  "started_unix": time.time(), "timed_out": False}
        encoded = None if payload is None else json.dumps(payload).encode()
        if encoded is not None:
            (self.output / "logs" / f"{stem}.stdin.json").write_bytes(encoded)
        try:
            result = subprocess.run(argv, input=encoded, capture_output=True, timeout=timeout,
                                    env={**os.environ, "LC_ALL": "C"})
            stdout, stderr = result.stdout, result.stderr
            record["returncode"] = result.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr = exc.stdout or b"", exc.stderr or b""
            record.update(returncode=None, timed_out=True)
        except OSError as exc:
            stdout, stderr = b"", str(exc).encode()
            record.update(returncode=None, launch_error=str(exc))
        record["elapsed_seconds"] = time.monotonic() - start
        for key, data in (("stdout", stdout), ("stderr", stderr)):
            target = self.output / "logs" / f"{stem}.{key}"
            target.write_bytes(data)
            record[key] = str(target)
        with self.events.open("a") as log:
            log.write(json.dumps(record, sort_keys=True) + "\n")
        return record


def successful(record: dict) -> bool:
    return record.get("returncode") == 0 and not record["timed_out"]


def manifest_status(manifest: dict) -> str:
    status = str(manifest.get("status", "")).lower()
    if status in {"ok", "success", "complete", "completed"}:
        return "ok"
    if status in {"unsupported", "error", "failed", "rejected", "invalid"}:
        return status
    if manifest.get("accepted") is True:
        return "ok"
    if manifest.get("accepted") is False:
        return "rejected"
    return "missing_status"


def generated_source(manifest: dict, directory: Path) -> Path:
    output_files = manifest.get("output_files", {})
    candidate = output_files.get("decompiled_c") if isinstance(output_files, dict) else None
    if not candidate:
        candidate = manifest.get("decompiled_c", "decompiled.c")
    if not isinstance(candidate, str):
        raise ValueError("decompiled C path must be a string")
    path = Path(candidate)
    path = (path if path.is_absolute() else directory / path).resolve()
    if not path.is_relative_to(directory.resolve()):
        raise ValueError("decompiled C must be an artifact inside its fresh output directory")
    return path


def run(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    cli = Path(args.cli).resolve()
    if not cli.is_file():
        raise SystemExit(f"CLI does not exist: {cli}")
    output.mkdir(parents=True, exist_ok=False)
    for directory in ("logs", "source-snapshot", "candidate", "original", "decompilations", "generated"):
        (output / directory).mkdir()
    config = json.loads((ROOT / "fixtures/corpus.json").read_text())
    provenance = {"cli": digest(cli), "sources": []}
    frozen_cli = output / "candidate" / "rust-ghidra"
    shutil.copy2(cli, frozen_cli)
    provenance["frozen_cli"] = digest(frozen_cli)
    if provenance["cli"]["sha256"] != provenance["frozen_cli"]["sha256"]:
        raise RuntimeError("candidate changed while being copied")
    for source in [ROOT / "fixtures/scalar.c", ROOT / "fixtures/reject.S",
                   ROOT / "fixtures/corpus.json", Path(__file__).resolve()]:
        relative = source.relative_to(ROOT)
        snapshot = output / "source-snapshot" / relative
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, snapshot)
        provenance["sources"].append(digest(source))
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    vectors = inputs(config)
    (output / "inputs.json").write_text(json.dumps(vectors) + "\n")
    commands = Commands(output)
    commands.run("compiler-version", [args.cc, "--version"])
    cases, errors = [], []
    summary = {"schema": 1, "status": "running", "scope": config["scope"],
               "input_vectors": len(vectors), "cases": cases, "errors": errors,
               "supported_expected": len(config["supported"]) * len(config["optimization_levels"]),
               "reject_expected": len(config["must_reject"]) * len(config["optimization_levels"])}
    try:
        for optimization in config["optimization_levels"]:
            library = output / "original" / f"scalar-{optimization}.so"
            compile_original = commands.run(f"compile-original-{optimization}", [args.cc, f"-{optimization}",
                *config["cflags"], str(output / "source-snapshot/fixtures/scalar.c"),
                str(output / "source-snapshot/fixtures/reject.S"), "-o", str(library)])
            if not successful(compile_original):
                errors.append({"optimization": optimization, "stage": "compile_original", "command": compile_original})
                continue
            for name in [*config["supported"], *config["must_reject"]]:
                should_support = name in config["supported"]
                case = {"optimization": optimization, "function": name, "expected_supported": should_support,
                        "status": "running"}
                cases.append(case)
                directory = output / "decompilations" / f"{optimization}-{name}"
                invocation = commands.run(f"decompile-{optimization}-{name}", [str(frozen_cli), "decompile", str(library),
                    "--function", name, "--output", str(directory)], timeout=args.decompile_timeout)
                case["decompile_command"] = invocation
                manifest_path = directory / "manifest.json"
                if invocation["timed_out"] or not manifest_path.is_file():
                    case["status"] = "decompile_timeout" if invocation["timed_out"] else "missing_manifest"
                    continue
                try:
                    manifest = json.loads(manifest_path.read_text())
                    if not isinstance(manifest, dict):
                        raise ValueError("manifest must be a JSON object")
                    source = generated_source(manifest, directory)
                except (ValueError, OSError) as exc:
                    case.update(status="invalid_manifest", error=str(exc))
                    continue
                case["manifest"] = str(manifest_path)
                case["reported_status"] = manifest_status(manifest)
                if not should_support:
                    if (case["reported_status"] in {"unsupported", "error", "failed", "rejected", "invalid"}
                            and invocation.get("returncode") == 1 and not source.exists()):
                        case["status"] = "rejected_as_required"
                    else:
                        case["status"] = "unsafe_acceptance_or_invalid_rejection"
                    continue
                if case["reported_status"] != "ok":
                    case["status"] = "unsupported_expected_supported" if case["reported_status"] == "unsupported" else "decompile_error"
                    continue
                if not successful(invocation) or not source.is_file():
                    case["status"] = "inconsistent_success"
                    continue
                generated = output / "generated" / f"{optimization}-{name}.so"
                compilation = commands.run(f"compile-generated-{optimization}-{name}", [args.cc, "-std=c11", "-O2",
                    "-fPIC", "-shared", "-nostdlib", "-fno-stack-protector", "-Wl,--build-id=none",
                    "-Werror=implicit-function-declaration", "-Werror=return-type", "-Werror=shift-count-negative",
                    "-Werror=shift-count-overflow", str(source), "-o", str(generated)])
                case["compile_command"] = compilation
                if not successful(compilation):
                    case["status"] = "generated_c_compile_error"
                    continue
                oracle = [expected(name, vector) for vector in vectors]
                outputs = {}
                generated_name = manifest.get("generated_function", name)
                for arm, path, function in (("original", library, name), ("generated", generated, generated_name)):
                    execution = commands.run(f"execute-{arm}-{optimization}-{name}", [sys.executable, str(Path(__file__).resolve()), "--worker"],
                        timeout=config["child_timeout_seconds"], payload={"library": str(path), "function": function, "inputs": vectors})
                    case[f"{arm}_command"] = execution
                    if not successful(execution):
                        case["status"] = f"{arm}_execution_error"
                        break
                    try:
                        outputs[arm] = json.loads(Path(execution["stdout"]).read_text())["outputs"]
                    except (ValueError, KeyError) as exc:
                        case.update(status=f"{arm}_invalid_output", error=str(exc))
                        break
                if case["status"] != "running":
                    continue
                mismatches = []
                for arm, actual in outputs.items():
                    if len(actual) != len(oracle):
                        mismatches.append({"arm": arm, "error": "wrong result count", "actual": len(actual), "expected": len(oracle)})
                        continue
                    mismatches.extend({"arm": arm, "index": i, "input": vectors[i], "expected": wanted, "actual": got}
                                      for i, (wanted, got) in enumerate(zip(oracle, actual)) if got != wanted)
                case["mismatch_count"] = len(mismatches)
                if mismatches:
                    mismatch_file = output / "generated" / f"{optimization}-{name}-mismatches.json"
                    mismatch_file.write_text(json.dumps(mismatches, indent=2) + "\n")
                    case.update(status="semantic_mismatch", mismatches=str(mismatch_file))
                else:
                    case.update(status="semantic_match", comparisons_per_arm=len(oracle))
    except Exception as exc:
        errors.append({"stage": "runner", "type": type(exc).__name__, "error": str(exc)})
    final_cli = digest(cli)
    provenance["cli_after"] = final_cli
    if final_cli != provenance["cli"]:
        errors.append({"stage": "provenance", "error": "candidate CLI changed during validation"})
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    counts = {}
    for case in cases:
        counts[case["status"]] = counts.get(case["status"], 0) + 1
    summary["counts"] = counts
    summary["artifacts"] = [digest(path) for directory in ("original", "generated")
                            for path in sorted((output / directory).glob("*.so"))]
    summary["commands"] = commands.count
    summary["supported_passed"] = counts.get("semantic_match", 0)
    summary["reject_passed"] = counts.get("rejected_as_required", 0)
    passed = not errors and summary["supported_passed"] == summary["supported_expected"] and summary["reject_passed"] == summary["reject_expected"]
    summary["status"] = "passed" if passed else "failed"
    (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({key: summary[key] for key in ("status", "counts", "supported_passed", "supported_expected", "reject_passed", "reject_expected", "input_vectors")}, indent=2))
    return 0 if passed else 1


def main() -> int:
    if "--worker" in sys.argv[1:]:
        return worker()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new result directory; existing paths are refused")
    parser.add_argument("--cli", required=True, help="native Rust executable")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--decompile-timeout", type=int, default=30)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
