#!/usr/bin/env python3
"""Fixed independent read-only image/pointer validation; run heavy work serially.

No numeric equality of native and reconstructed host pointers is meaningful.
Pointer results are compared as bounded byte strings against native content and
independent fixture/CRC expectations. Unsafe original guard functions are never
executed. A guard is accepted only as an explicit static unsupported result or
SIGABRT from the generated artifact, never as SIGSEGV or an arbitrary failure.
"""
from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
import resource
import shutil
import signal
import sys

import validate

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = Path("/usr/lib/x86_64-linux-gnu/libz.so.1.3.1")
BASELINE = ROOT / "results/real-zlib-01/decompilations/library-batch/manifest.json"
MASK = (1 << 64) - 1
BYTES = bytes.fromhex("00 ff 81 7e 19 a4 55 c3 02 61 e7 34 b8 0d 9a 46 f1 28 63 bd 05 92 4a d6 73 0b e0 5c a9 31 87 6f")
WORDS = [0, 0xffff, 0x8001, 0x7ffe, 0x19a4, 0x55c3, 0xe734, 0xb80d]
DWORDS = [0, 0xffffffff, 0x80000001, 0x7ffffffe, 0x19a455c3, 0xe734b80d, 0x9a46f128, 0x63bd0592]
QWORDS = [0, MASK, 0x8000000000000001, 0x7ffffffffffffffe, 0x19a455c3e734b80d,
          0x9a46f12863bd0592, 0x4ad6730be05ca931, 0x876f028161e734b8]
NUMERIC = ("image_u8", "image_u16", "image_u32", "image_u64", "image_pair", "image_loop", "image_same_object_delta")
POINTER = ("image_pointer_base", "image_pointer_offset", "image_pointer_spill")
GUARDS = (("image_guard_writable", "u64"), ("image_guard_write", "u64"),
          ("image_guard_external", "u64"), ("image_pointer_base", "u64"),
          ("image_guard_partial", "u64"), ("image_guard_oob", "u64"))
OPTIMIZATIONS = ("O0", "O2", "O3")
CFLAGS = ["-std=c11", "-fPIC", "-shared", "-nostdlib", "-fno-stack-protector",
          "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-fno-tree-vectorize",
          "-fno-tree-slp-vectorize", "-fcf-protection=none", "-Wl,--build-id=none"]


def expected(name: str, args: list[int]) -> int | str:
    a, b, c, _, _, _ = args
    if name == "image_u8": value = BYTES[a & 31] + b
    elif name == "image_u16": value = WORDS[a & 7] ^ b
    elif name == "image_u32": value = DWORDS[a & 7] + b
    elif name == "image_u64": value = QWORDS[a & 7] ^ b
    elif name == "image_pair": value = BYTES[a & 31] + (WORDS[b & 7] << 8) + c
    elif name == "image_loop": value = b + sum(BYTES[:(a & 7) + 1])
    elif name == "image_same_object_delta": value = (b & 15) - (a & 15)
    elif name in POINTER:
        offset = 0 if name == "image_pointer_base" else a & 15
        return BYTES[offset:offset + 16].hex()
    else: raise ValueError(f"missing formula: {name}")
    return value & MASK


def crc_prefix() -> bytes:
    """First 16 reflected IEEE CRC32 table entries, independent of zlib code."""
    result = bytearray()
    for i in range(16):
        value = i
        for _ in range(8):
            value = (value >> 1) ^ (0xedb88320 if value & 1 else 0)
        result.extend(value.to_bytes(4, "little"))
    return bytes(result)


def worker() -> int:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
    payload = json.load(sys.stdin)
    library = ctypes.CDLL(payload["library"])
    function = getattr(library, payload["function"])
    function.argtypes = [ctypes.c_uint64] * 6
    pointer = payload["return_kind"] == "pointer"
    function.restype = ctypes.c_void_p if pointer else ctypes.c_uint64
    outputs = []
    for values in payload["inputs"]:
        result = function(*values)
        if pointer:
            if result is None:
                raise ValueError("unexpected null pointer")
            outputs.append(ctypes.string_at(result, payload["read_bytes"]).hex())
        else:
            outputs.append(int(result))
    json.dump({"outputs": outputs}, sys.stdout)
    return 0


def freeze(source: Path, target: Path, provenance: dict) -> None:
    original = validate.digest(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    frozen = validate.digest(target)
    if original["sha256"] != frozen["sha256"]:
        raise RuntimeError(f"source changed during snapshot: {source}")
    provenance["sources"].append({"original": original, "frozen": frozen})


def require_outputs(record: dict, count: int, pointer: bool, width: int) -> list:
    if not validate.successful(record):
        raise ValueError("execution did not exit successfully")
    payload = json.loads(Path(record["stdout"]).read_text())
    outputs = payload["outputs"]
    if not isinstance(outputs, list) or len(outputs) != count:
        raise ValueError("worker must emit the exact output count")
    for value in outputs:
        if pointer:
            if not isinstance(value, str) or len(value) != width * 2 or bytes.fromhex(value).hex() != value:
                raise ValueError("pointer output must be an exact lowercase byte string")
        elif type(value) is not int or not 0 <= value <= MASK:
            raise ValueError("numeric output must be unsigned u64")
    return outputs


def decompile(commands: validate.Commands, cli: Path, library: Path, name: str,
              kind: str, directory: Path, timeout: int, case: dict) -> tuple[dict, Path] | None:
    command = commands.run(f"decompile-{directory.name}", [str(cli), "decompile", str(library),
        "--function", name, "--return", kind, "--output", str(directory)], timeout=timeout)
    case["decompile_command"] = command
    manifest_path = directory / "manifest.json"
    case["manifest"] = str(manifest_path)
    if command["timed_out"] or not manifest_path.is_file():
        case["status"] = "decompile_timeout" if command["timed_out"] else "missing_manifest"
        return None
    try:
        manifest = json.loads(manifest_path.read_text())
        if not isinstance(manifest, dict): raise ValueError("manifest must be an object")
        source = validate.generated_source(manifest, directory)
        case["reported_status"] = validate.manifest_status(manifest)
        if case["reported_status"] == "ok":
            if (not validate.successful(command) or manifest.get("backend") != "native-rust"
                    or manifest.get("guarded") is not True or manifest.get("return_kind") != kind
                    or not isinstance(manifest.get("generated_function"), str)
                    or not manifest["generated_function"].isidentifier() or not source.is_file()):
                raise ValueError("accepted manifest lacks validated result model/backend/artifact")
        elif validate.successful(command):
            raise ValueError("non-success manifest must return nonzero")
        return manifest, source
    except (ValueError, KeyError, TypeError, OSError) as exc:
        case.update(status="invalid_manifest", error=str(exc))
        return None


def compile_generated(commands: validate.Commands, cc: str, source: Path, library: Path, case: dict) -> bool:
    command = commands.run(f"compile-{library.stem}", [cc, "-O2", *CFLAGS,
        "-Werror=implicit-function-declaration", "-Werror=return-type",
        "-Werror=shift-count-negative", "-Werror=shift-count-overflow", str(source), "-o", str(library)])
    case["compile_command"] = command
    if not validate.successful(command):
        case["status"] = "compile_failed"
        return False
    return True


def execute(commands: validate.Commands, script: Path, library: Path, name: str,
            kind: str, vectors: list, width: int, label: str) -> dict:
    return commands.run(label, [sys.executable, str(script), "--worker"], timeout=5,
        payload={"library": str(library), "function": name, "return_kind": kind,
                 "inputs": vectors, "read_bytes": width})


def positive(commands: validate.Commands, args: argparse.Namespace, cli: Path, library: Path,
             name: str, kind: str, label: str, vectors: list, wanted: list,
             width: int, output: Path, script: Path, cases: list) -> None:
    case = {"function": name, "return_kind": kind, "build": label,
            "expected": "semantic_match", "status": "running"}
    cases.append(case)
    parsed = decompile(commands, cli, library, name, kind,
        output / "decompilations" / f"{label}-{name}-{kind}", args.decompile_timeout, case)
    if parsed is None: return
    manifest, source = parsed
    if case["reported_status"] != "ok":
        case.update(status="unexpected_rejection", reason=manifest.get("error"))
        return
    generated = output / "generated" / f"{label}-{name}-{kind}.so"
    if not compile_generated(commands, args.cc, source, generated, case): return
    observed = {}
    for arm, arm_library, arm_name in (("original", library, name), ("generated", generated, manifest["generated_function"])):
        command = execute(commands, script, arm_library, arm_name, kind, vectors, width,
                          f"execute-{label}-{name}-{arm}")
        case[f"{arm}_command"] = command
        try: observed[arm] = require_outputs(command, len(vectors), kind == "pointer", width)
        except (ValueError, KeyError, OSError) as exc:
            case.update(status="execution_failed", error=str(exc), arm=arm)
    if len(observed) != 2: return
    mismatches = [{"arm": arm, "input": vectors[i], "expected": target, "actual": value}
                  for arm, values in observed.items() for i, (target, value) in enumerate(zip(wanted, values))
                  if target != value]
    case["mismatch_count"] = len(mismatches)
    if mismatches:
        path = output / "generated" / f"{label}-{name}-{kind}-mismatches.json"
        path.write_text(json.dumps(mismatches, indent=2) + "\n")
        case.update(status="semantic_mismatch", mismatches=str(path))
    else:
        case.update(status="semantic_match", comparisons_per_arm=len(vectors),
                    oracle="native execution plus independent constants/formula",
                    read_bytes=width if kind == "pointer" else None)


def guard(commands: validate.Commands, args: argparse.Namespace, cli: Path, library: Path,
          name: str, kind: str, label: str, output: Path, script: Path, cases: list) -> None:
    case = {"function": name, "return_kind": kind, "build": label,
            "expected": "unsupported_or_sigabrt", "status": "running"}
    cases.append(case)
    parsed = decompile(commands, cli, library, name, kind,
        output / "decompilations" / f"guard-{label}-{name}-{kind}", args.decompile_timeout, case)
    if parsed is None: return
    manifest, source = parsed
    if (case["reported_status"] == "unsupported" and case["decompile_command"].get("returncode") == 1
            and not source.exists() and isinstance(manifest.get("error"), str) and manifest["error"]):
        case.update(status="guarded_as_required", mechanism="static_unsupported", reason=manifest["error"])
        return
    if case["reported_status"] != "ok":
        case.update(status="invalid_guard_rejection", reason=manifest.get("error"))
        return
    generated = output / "generated" / f"guard-{label}-{name}-{kind}.so"
    if not compile_generated(commands, args.cc, source, generated, case): return
    command = execute(commands, script, generated, manifest["generated_function"], kind,
                      [[0, 0, 0, 0, 0, 0]], 1, f"guard-execute-{label}-{name}")
    case["execution_command"] = command
    if not command["timed_out"] and command.get("returncode") == -signal.SIGABRT:
        case.update(status="guarded_as_required", mechanism="generated_sigabrt")
    else:
        case.update(status="guard_failed", observed_returncode=command.get("returncode"))


def body_map(manifest: dict) -> list[tuple]:
    rows = manifest["functions"]
    if not isinstance(rows, list): raise ValueError("batch functions must be an array")
    return sorted((row["function"]["address"], row["function"]["size"], row["function"]["file_offset"])
                  for row in rows)


def coverage(commands: validate.Commands, args: argparse.Namespace, cli: Path, library: Path,
             output: Path, baseline: dict, summary: dict) -> None:
    reports = {}
    frozen_map = body_map(baseline)
    if len(frozen_map) != 88 or len(set(frozen_map)) != 88:
        raise ValueError("historical body-map denominator is not the frozen 88 distinct extents")
    for kind in ("u64", "pointer"):
        directory = output / "decompilations" / f"zlib-batch-{kind}"
        command = commands.run(f"analyze-zlib-{kind}", [str(cli), "analyze", str(library),
            "--return", kind, "--max-functions", "1000", "--output", str(directory)], timeout=args.analyze_timeout)
        manifest = json.loads((directory / "manifest.json").read_text())
        rows = manifest["functions"]
        accepted = sum(row.get("status") == "ok" for row in rows)
        unsupported = sum(row.get("status") == "unsupported" for row in rows)
        if (command["timed_out"] or command.get("returncode") != 1 or manifest.get("status") != "partial"
                or manifest.get("truncated") is not False or manifest.get("backend") != "native-rust"
                or manifest.get("return_kind") != kind or manifest.get("function_count") != 88
                or manifest.get("attempted_count") != 88 or body_map(manifest) != frozen_map
                or accepted != manifest.get("decompiled_count") or unsupported != manifest.get("unsupported_count")
                or accepted + unsupported != 88):
            raise ValueError(f"{kind} batch violates fixed-body-map/status/count contract")
        reports[kind] = {"manifest": str(directory / "manifest.json"), "command": command,
            "artifact_count": accepted, "unsupported_count": unsupported,
            "artifact_bodies": [row["function"]["address"] for row in rows if row["status"] == "ok"]}
    union = set(reports["u64"]["artifact_bodies"]) | set(reports["pointer"]["artifact_bodies"])
    pointer_targets = ["zlibVersion", "get_crc_table"]
    validated = [name for name in pointer_targets if any(case["function"] == name
        and case["build"] == "zlib" and case["return_kind"] == "pointer"
        and case["status"] == "semantic_match" for case in summary["cases"])]
    summary["coverage"] = {"frozen_denominator": 88, "return_models": reports,
        "union_artifact_bodies": len(union), "new_pointer_execution_validation_expected": pointer_targets,
        "new_pointer_execution_validated": validated,
        "interpretation": "artifacts are guarded C under an explicit result model, not proof of supported arbitrary ABI/input behavior; execution-validated pointer functions are listed from successful content checks"}


def run(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    cli = Path(args.cli).resolve()
    if not all(path.is_file() for path in (cli, LIBRARY, BASELINE)):
        raise SystemExit("CLI, installed zlib, and frozen historical coverage are required")
    output.mkdir(parents=True, exist_ok=False)
    for name in ("logs", "candidate", "input", "original", "source-snapshot", "decompilations", "generated"):
        (output / name).mkdir()
    provenance = {"sources": [], "python": validate.digest(Path(sys.executable).resolve())}
    frozen_cli, library = output / "candidate/rust-ghidra", output / "input/libz.so.1.3.1"
    for source, target in ((cli, frozen_cli), (LIBRARY, library),
                           (ROOT / "fixtures/image-data.c", output / "source-snapshot/fixtures/image-data.c"),
                           (Path(__file__).resolve(), output / "source-snapshot/review/image_validation.py"),
                           (ROOT / "review/validate.py", output / "source-snapshot/review/validate.py"),
                           (ROOT / "fixtures/corpus.json", output / "source-snapshot/fixtures/corpus.json"),
                           (BASELINE, output / "source-snapshot/frozen-zlib-batch.json")):
        freeze(source, target, provenance)
    script = output / "source-snapshot/review/image_validation.py"
    config = json.loads((output / "source-snapshot/fixtures/corpus.json").read_text())
    vectors = validate.inputs(config)
    # All table indices, pointer offsets, and subtraction orderings are explicit.
    vectors = [list(row) for row in dict.fromkeys(map(tuple,
        vectors + [[a, b, MASK - a, 0, 0, 0] for a in range(32) for b in range(16)]))]
    (output / "inputs.json").write_text(json.dumps(vectors) + "\n")
    contract = {"positive": {"numeric": NUMERIC, "pointer": POINTER}, "guards": GUARDS,
        "optimization_levels": OPTIMIZATIONS, "cflags": CFLAGS,
        "input_count": len(vectors), "zlib": {"zlibVersion": {"read_bytes": 6, "expected_hex": b"1.3.1\0".hex()},
                                               "get_crc_table": {"read_bytes": 64, "expected_hex": crc_prefix().hex()}},
        "coverage_baseline": validate.digest(BASELINE), "frozen_denominator": 88}
    (output / "contract.json").write_text(json.dumps(contract, indent=2) + "\n")
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    commands = validate.Commands(output)
    cases, errors = [], []
    summary = {"schema": 1, "status": "running", "input_vectors": len(vectors), "cases": cases, "errors": errors,
        "positive_expected": len(OPTIMIZATIONS) * (len(NUMERIC) + len(POINTER)) + 2,
        "guard_expected": len(OPTIMIZATIONS) * len(GUARDS) + 2,
        "scope": "file-backed read-only image loads and explicit pointer results; no mutable/external pointer memory"}
    try:
        commands.run("compiler-version", [args.cc, "--version"])
        for optimization in OPTIMIZATIONS:
            original = output / "original" / f"image-{optimization}.so"
            command = commands.run(f"compile-original-{optimization}", [args.cc, f"-{optimization}", *CFLAGS,
                str(output / "source-snapshot/fixtures/image-data.c"), "-o", str(original)])
            if not validate.successful(command):
                errors.append({"stage": "compile_original", "optimization": optimization, "command": command})
                continue
            for name in (*NUMERIC, *POINTER):
                kind = "pointer" if name in POINTER else "u64"
                positive(commands, args, frozen_cli, original, name, kind, optimization, vectors,
                    [expected(name, values) for values in vectors], 16 if kind == "pointer" else 0,
                    output, script, cases)
            for name, kind in GUARDS:
                guard(commands, args, frozen_cli, original, name, kind, optimization, output, script, cases)
        for name, width, contents in (("zlibVersion", 6, b"1.3.1\0"), ("get_crc_table", 64, crc_prefix())):
            positive(commands, args, frozen_cli, library, name, "pointer", "zlib", vectors,
                [contents.hex()] * len(vectors), width, output, script, cases)
            guard(commands, args, frozen_cli, library, name, "u64", "zlib", output, script, cases)
        coverage(commands, args, frozen_cli, library, output,
                 json.loads((output / "source-snapshot/frozen-zlib-batch.json").read_text()), summary)
    except Exception as exc:
        errors.append({"stage": "runner", "type": type(exc).__name__, "error": str(exc)})
    for row in provenance["sources"]:
        for key in ("original", "frozen"):
            after = validate.digest(Path(row[key]["path"]))
            row[f"{key}_after"] = after
            if row[key] != after: errors.append({"stage": "provenance", "error": f"source changed: {row[key]['path']}"})
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    counts = {}
    for case in cases: counts[case["status"]] = counts.get(case["status"], 0) + 1
    summary["counts"], summary["commands"] = counts, commands.count
    summary["artifacts"] = [validate.digest(path) for path in sorted((output / "generated").glob("*.so"))]
    summary["status"] = "passed" if (not errors and counts.get("semantic_match", 0) == summary["positive_expected"]
        and counts.get("guarded_as_required", 0) == summary["guard_expected"] and "coverage" in summary) else "failed"
    (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({key: summary.get(key) for key in ("status", "input_vectors", "counts", "coverage", "errors")}, indent=2))
    return 0 if summary["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--output", help="new result directory; existing paths refused")
    parser.add_argument("--cli", help="candidate standalone Rust decompiler")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--decompile-timeout", type=int, default=30)
    parser.add_argument("--analyze-timeout", type=int, default=90)
    args = parser.parse_args()
    if args.worker: return worker()
    if not args.output or not args.cli: parser.error("--output and --cli are required")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
