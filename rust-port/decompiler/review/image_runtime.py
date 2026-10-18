#!/usr/bin/env python3
"""Direct multi-object/provenance behavior gate for the generated C runtime.

Run only during an exclusive heavy-work slot. All expected values below derive
from fixed fixture bytes and offsets; guards must terminate with SIGABRT.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

import validate as common

ROOT = Path(__file__).resolve().parents[1]
FIRST = bytes(range(0x10, 0x30))
SECOND = bytes(range(0xa0, 0xb8))
POSITIVES = {
    "load_widths": {"values": [int.from_bytes(FIRST[3:3 + n], "little") for n in (1, 2, 4, 8)]},
    "last_word": {"value": int.from_bytes(SECOND[16:24], "little")},
    "pointer_offset": {"object": 2, "offset": 5, "byte": SECOND[5]},
    "pointer_one_past": {"object": 1, "offset": len(FIRST), "byte": -1},
    "same_object_subtract": {"value": 17, "known_flags": 0},
    "same_object_compare_equal": {"zf": 1, "not_zf": 0, "known_flags": 4},
    "same_object_compare_unequal": {"zf": 0, "not_zf": 1, "known_flags": 4},
    "scalar_plus_pointer": {"object": 2, "offset": 8, "byte": SECOND[8]},
    "pointer_minus_scalar": {"object": 2, "offset": 5, "byte": SECOND[5]},
    "lea_index": {"object": 1, "offset": 15, "byte": FIRST[15]},
    "full_spill": {"object": 2, "offset": 7, "byte": SECOND[7]},
    "replace_spill_origin": {"object": 2, "offset": 11, "byte": SECOND[11]},
    "unaligned_spill": {"object": 1, "offset": 3, "byte": FIRST[3]},
    "scalar_replaces_spill": {"value": 0x1122334455667788},
    "stack_spill": {"value": 0x6a},
}
GUARDS = [
    "cross_object_subtract", "cross_object_compare", "pointer_compare_cf",
    "pointer_compare_of", "pointer_compare_sf", "pointer_compare_pf",
    "image_bitwise", "numeric_reification",
    "stack_pointer_result", "scalar_pointer_result", "invalid_pointer_result",
    "unknown_pointer_result", "past_pointer_result", "one_past_read",
    "cross_end_read", "far_read", "image_write", "partial_spill", "split_origins",
    "overlapping_stores", "partial_scalar_overwrite", "truncated_register",
    "pointer_flags", "scaled_pointer_index", "two_pointer_lea", "pointer_narrow_alu",
    "invalid_object_zero", "invalid_object_high", "absent_object_table",
]


def run(arguments: argparse.Namespace) -> int:
    output = Path(arguments.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "logs").mkdir()
    snapshot = output / "source-snapshot"
    snapshot.mkdir()
    runtime = Path(arguments.runtime).resolve()
    sources = [(runtime, Path("src/runtime.h")),
               (ROOT / "fixtures/image-runtime.c", Path("fixtures/image-runtime.c")),
               (Path(__file__).resolve(), Path("review/image_runtime.py")),
               (Path(common.__file__).resolve(), Path("review/validate.py"))]
    provenance = {"runtime": common.digest(runtime), "sources": []}
    for original, relative in sources:
        frozen = snapshot / relative
        frozen.parent.mkdir(parents=True, exist_ok=True)
        before = common.digest(original)
        shutil.copy2(original, frozen)
        copied = common.digest(frozen)
        if (before["sha256"], before["bytes"]) != (copied["sha256"], copied["bytes"]):
            raise RuntimeError(f"source changed while freezing: {original}")
        provenance["sources"].append({"original": before, "frozen": copied})
    compiler = shutil.which(arguments.cc)
    if compiler is not None:
        provenance["compiler"] = common.digest(Path(compiler).resolve())
    provenance_path = output / "provenance.json"
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    (output / "selection.json").write_text(json.dumps({"positives": POSITIVES, "guards": GUARDS,
        "first_hex": FIRST.hex(), "second_hex": SECOND.hex()}, indent=2) + "\n")
    commands = common.Commands(output)
    executable = output / "image-runtime"
    cases, errors = [], []
    try:
        compile_result = commands.run("compile-runtime", [arguments.cc, "-std=c11", "-O2",
            "-fno-stack-protector", "-Werror=implicit-function-declaration", "-Werror=return-type",
            "-Wl,--build-id=none", "-I", str(snapshot / "src"),
            str(snapshot / "fixtures/image-runtime.c"), "-o", str(executable)])
        if not common.successful(compile_result):
            raise RuntimeError("runtime fixture compilation failed")
        for name, expected in POSITIVES.items():
            execution = commands.run(f"positive-{name}", [str(executable), name], timeout=5)
            case = {"name": name, "guard": False, "expected": expected, "command": execution}
            cases.append(case)
            if not common.successful(execution):
                case["status"] = "execution_error"
                continue
            try:
                actual = json.loads(Path(execution["stdout"]).read_text())
                case.update(actual=actual, status="matched" if actual == expected else "mismatch")
            except (OSError, json.JSONDecodeError) as exception:
                case.update(status="invalid_output", error=str(exception))
        for name in GUARDS:
            execution = commands.run(f"guard-{name}", [str(executable), name], timeout=5)
            cases.append({"name": name, "guard": True, "command": execution,
                "status": "guard_aborted" if execution.get("returncode") == -6
                    and not execution["timed_out"] else "guard_failed"})
    except Exception as exception:
        errors.append({"stage": "runner", "type": type(exception).__name__, "error": str(exception)})
    provenance["runtime_after"] = common.digest(runtime)
    if provenance["runtime_after"] != provenance["runtime"]:
        errors.append({"stage": "provenance", "error": "runtime changed during the fixed gate"})
    for record in provenance["sources"]:
        original_after = common.digest(Path(record["original"]["path"]))
        frozen_after = common.digest(Path(record["frozen"]["path"]))
        record.update(original_after=original_after, frozen_after=frozen_after)
        if original_after != record["original"] or frozen_after != record["frozen"]:
            errors.append({"stage": "provenance", "error": "source changed during the fixed gate",
                "path": record["original"]["path"]})
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    counts = {}
    for case in cases:
        counts[case["status"]] = counts.get(case["status"], 0) + 1
    passed = (not errors and counts.get("matched", 0) == len(POSITIVES)
        and counts.get("guard_aborted", 0) == len(GUARDS))
    results = {"schema": 1, "status": "passed" if passed else "failed",
        "scope": "direct generated-C runtime, two immutable image objects, scalar inputs",
        "expected_positive_cases": len(POSITIVES), "expected_guard_cases": len(GUARDS),
        "counts": counts, "cases": cases, "errors": errors, "commands": commands.count,
        "artifacts": [common.digest(executable)] if executable.is_file() else []}
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({key: results[key] for key in ("status", "counts", "errors")}, indent=2))
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--runtime", default=str(ROOT / "src/runtime.h"))
    parser.add_argument("--cc", default="gcc")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
