#!/usr/bin/env python3
"""Independent fixed execution/provenance gate for read-only image support.

Run only in an exclusive heavy-work slot. Guard functions execute only in the
generated arm and must explicitly reject or SIGABRT, never segfault/time out.
"""
from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
import resource
import shutil
import sys

import validate as common

ROOT = Path(__file__).resolve().parents[1]
TABLE = bytes((3 + 17 * index) & 255 for index in range(64))
NUMERIC = ["edge_image_load8", "edge_image_load64", "edge_image_spill_load",
           "edge_image_negative_load", "edge_image_pointer_je", "edge_image_pointer_jne"]
POINTER = ["edge_image_pointer_base", "edge_image_pointer_index", "edge_image_pointer_spill"]
GUARDS = {
    "guard_image_numeric_alias": "u64",
    "guard_image_truncate": "u64",
    "guard_image_partial_register": "u64",
    "guard_image_numeric_return": "u64",
    "guard_image_write": "u64",
    "guard_image_far_oob": "u64",
    "guard_image_cross_end": "u64",
    "guard_image_scalar_pointer_return": "pointer",
    "guard_image_align_mask": "pointer",
    "guard_image_pointer_flags": "u64",
    "guard_image_cmp_cf": "u64",
    "guard_image_cmp_of": "u64",
    "guard_image_partial_spill": "pointer",
    "guard_image_split_spill": "pointer",
    "guard_image_stack_pointer_return": "pointer",
    "guard_image_immediate_pointer_return": "pointer",
    "guard_image_writable_load": "u64",
}


def expected(name: str, arguments: list[int]):
    index = arguments[0]
    if name == "edge_image_load64":
        at = index & 31
        return int.from_bytes(TABLE[at:at + 8], "little")
    if name in {"edge_image_load8", "edge_image_spill_load"}:
        return TABLE[index & 63]
    if name == "edge_image_negative_load":
        return TABLE[32 - (index & 31)]
    if name == "edge_image_pointer_je":
        return 77 if (index & 63) == (arguments[1] & 63) else 19
    if name == "edge_image_pointer_jne":
        return 93 if (index & 63) != (arguments[1] & 63) else 7
    if name in POINTER:
        offset = 0 if name == "edge_image_pointer_base" else index & 63
        return {"offset": offset, "contents_hex": TABLE[offset:offset + 1].hex()}
    raise ValueError(name)


def worker() -> int:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
    payload = json.load(sys.stdin)
    library = ctypes.CDLL(payload["library"])
    function = getattr(library, payload["function"])
    function.argtypes = [ctypes.c_uint64] * 6
    function.restype = ctypes.c_void_p if payload["return_kind"] == "pointer" else ctypes.c_uint64
    if payload.get("guard"):
        # Do not dereference unexpected guard results: any ordinary return fails.
        outputs = [function(*vector) for vector in payload["inputs"]]
    elif payload["return_kind"] == "pointer":
        base = function(0, 0, 0, 0, 0, 0)
        if base is None:
            raise ValueError("supported base pointer unexpectedly null")
        outputs = []
        for vector in payload["inputs"]:
            address = function(*vector)
            if address is None:
                raise ValueError("supported pointer unexpectedly null")
            outputs.append({"offset": int(address) - int(base),
                            "contents_hex": ctypes.string_at(address, 1).hex()})
    else:
        outputs = [int(function(*vector)) for vector in payload["inputs"]]
    json.dump({"outputs": outputs}, sys.stdout)
    return 0


def run(arguments: argparse.Namespace) -> int:
    output = Path(arguments.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name in ("logs", "source-snapshot", "candidate", "generated", "decompilations"):
        (output / name).mkdir()
    cli = Path(arguments.cli).resolve()
    candidate = output / "candidate/rust-ghidra"
    shutil.copy2(cli, candidate)
    sources = [ROOT / "fixtures/image-edges.S", Path(__file__).resolve(), Path(common.__file__).resolve()]
    provenance = {"cli": common.digest(cli), "candidate": common.digest(candidate), "sources": []}
    if provenance["cli"]["sha256"] != provenance["candidate"]["sha256"]:
        raise RuntimeError("candidate changed while copying")
    for source in sources:
        target = output / "source-snapshot" / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        provenance["sources"].append(common.digest(source))
    provenance_path = output / "provenance.json"
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    commands = common.Commands(output)
    vectors = common.inputs({"input_seed": 0x3A46D2E1, "random_input_count": 256})
    # Every table byte is observed independently of random-vector coverage.
    vectors.extend([[index, 0, 0, 0, 0, 0] for index in range(64)])
    vectors = [list(vector) for vector in dict.fromkeys(map(tuple, vectors))]
    (output / "inputs.json").write_text(json.dumps(vectors) + "\n")
    (output / "selection.json").write_text(json.dumps({"numeric": NUMERIC, "pointer": POINTER,
        "guards": GUARDS, "table_hex": TABLE.hex()}, indent=2) + "\n")
    worker_path = output / "source-snapshot/review/image_edges.py"
    original = output / "original.so"
    cases, errors = [], []
    try:
        compiled = commands.run("compile-original", [arguments.cc, "-shared", "-fPIC", "-nostdlib",
            "-Wl,--build-id=none", str(output / "source-snapshot/fixtures/image-edges.S"), "-o", str(original)])
        if not common.successful(compiled):
            raise RuntimeError("original fixture compilation failed")
        for name in NUMERIC + POINTER + list(GUARDS):
            mode = "pointer" if name in POINTER else GUARDS.get(name, "u64")
            is_guard = name in GUARDS
            case = {"function": name, "return_kind": mode, "guard": is_guard, "status": "running"}
            cases.append(case)
            directory = output / "decompilations" / name
            argv = [str(candidate), "decompile", str(original), "--function", name, "--output", str(directory)]
            if mode == "pointer":
                argv.extend(["--return", "pointer"])
            invoked = commands.run(f"decompile-{name}", argv)
            case["decompile_command"] = invoked
            manifest_path = directory / "manifest.json"
            if invoked["timed_out"] or not manifest_path.is_file():
                case["status"] = "decompile_timeout" if invoked["timed_out"] else "missing_manifest"
                continue
            manifest = json.loads(manifest_path.read_text())
            source = common.generated_source(manifest, directory)
            status = common.manifest_status(manifest)
            if status in {"unsupported", "error", "failed", "rejected", "invalid"}:
                case["status"] = ("guard_rejected" if is_guard and status == "unsupported"
                    and invoked.get("returncode") == 1 and not source.exists()
                    and isinstance(manifest.get("error"), str) and manifest["error"] else "unexpected_rejection")
                continue
            if (not common.successful(invoked) or status != "ok" or not source.is_file()
                    or manifest.get("backend") != "native-rust" or manifest.get("guarded") is not True):
                case["status"] = "inconsistent_success"
                continue
            if manifest.get("return_kind") != mode:
                case.update(status="return_kind_mismatch", observed=manifest.get("return_kind"))
                continue
            generated = output / "generated" / f"{name}.so"
            compilation = commands.run(f"compile-generated-{name}", [arguments.cc, "-std=c11", "-O2", "-shared",
                "-fPIC", "-nostdlib", "-fno-stack-protector", "-Wl,--build-id=none",
                "-Werror=implicit-function-declaration", "-Werror=return-type", str(source), "-o", str(generated)])
            case["compile_command"] = compilation
            if not common.successful(compilation):
                case["status"] = "generated_compile_error"
                continue
            generated_name = manifest["generated_function"]
            if is_guard:
                execution = commands.run(f"guard-generated-{name}", [sys.executable, str(worker_path), "--worker"],
                    timeout=5, payload={"library": str(generated), "function": generated_name,
                        "return_kind": mode, "guard": True, "inputs": [[1, 2, 3, 4, 5, 6]]})
                case.update(status="guard_aborted" if execution.get("returncode") == -6 and not execution["timed_out"]
                            else "guard_failed", execution=execution)
                continue
            wanted = [expected(name, vector) for vector in vectors]
            mismatches = []
            for arm, library, function in (("original", original, name), ("generated", generated, generated_name)):
                execution = commands.run(f"execute-{arm}-{name}", [sys.executable, str(worker_path), "--worker"],
                    timeout=5, payload={"library": str(library), "function": function, "return_kind": mode, "inputs": vectors})
                case[f"{arm}_command"] = execution
                if not common.successful(execution):
                    case["status"] = f"{arm}_execution_error"
                    break
                actual = json.loads(Path(execution["stdout"]).read_text())["outputs"]
                if len(actual) != len(wanted):
                    mismatches.append({"arm": arm, "error": "result_count", "expected": len(wanted), "actual": len(actual)})
                mismatches.extend({"arm": arm, "index": index, "input": vectors[index], "expected": expected_value,
                    "actual": actual_value} for index, (expected_value, actual_value) in enumerate(zip(wanted, actual))
                    if actual_value != expected_value)
            if case["status"] != "running":
                continue
            if mismatches:
                path = output / "generated" / f"{name}-mismatches.json"
                path.write_text(json.dumps(mismatches, indent=2) + "\n")
                case.update(status="semantic_mismatch", mismatch_count=len(mismatches), mismatches=str(path))
            else:
                case.update(status="semantic_match", comparisons_per_arm=len(vectors))
    except Exception as exception:
        errors.append({"stage": "runner", "type": type(exception).__name__, "error": str(exception)})
    provenance["cli_after"] = common.digest(cli)
    provenance["candidate_after"] = common.digest(candidate)
    if provenance["cli_after"] != provenance["cli"] or provenance["candidate_after"] != provenance["candidate"]:
        errors.append({"stage": "provenance", "error": "candidate changed during the fixed gate"})
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    counts = {}
    for case in cases:
        counts[case["status"]] = counts.get(case["status"], 0) + 1
    passed = (not errors and counts.get("semantic_match", 0) == len(NUMERIC) + len(POINTER)
        and counts.get("guard_rejected", 0) + counts.get("guard_aborted", 0) == len(GUARDS))
    results = {"schema": 1, "status": "passed" if passed else "failed", "scope": "ELF read-only image provenance",
        "input_vectors": len(vectors), "numeric_expected": len(NUMERIC), "pointer_expected": len(POINTER),
        "guards_expected": len(GUARDS), "cases": cases, "errors": errors, "counts": counts, "commands": commands.count,
        "artifacts": [common.digest(path) for path in [original, *sorted((output / "generated").glob("*.so"))] if path.is_file()]}
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({key: results[key] for key in ("status", "input_vectors", "counts", "errors")}, indent=2))
    return 0 if passed else 1


def main() -> int:
    if "--worker" in sys.argv[1:]:
        return worker()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--cc", default="gcc")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
