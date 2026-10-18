#!/usr/bin/env python3
"""Fixed independent ISA edge gate, separate from the source compiler corpus.

This runner imports only logging/worker helpers from validate.py. Expectations
below are new mathematical formulas, not results from the Rust implementation.
Guard cases must reject or abort; they are never executed in the original arm.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

import validate as common

MASK = (1 << 64) - 1
SUPPORTED = ["edge_adc_flags", "edge_sbb_flags", "edge_partial_bytes", "edge_partial_word",
             "edge_cmov32", "edge_shift_zero_zf", "edge_shift_zero_cf", "edge_sar64",
             "edge_rotate8_cf", "edge_rotate64_cf", "edge_shift8_value", "edge_imul_flags",
             "edge_push_pop_unknown", "edge_sbb_unknown_self", "edge_inc_preserves_cf",
             "edge_sign8_to32", "edge_sign32_to64"]
GUARDS = ["guard_stack_escape", "guard_undefined_entry_flags", "guard_undefined_imul_zf",
          "guard_undefined_shift_of", "guard_stack_return_corrupt", "guard_stack_align32",
          "guard_stack_numeric_alias"]


def oracle(name: str, args: list[int]) -> int:
    a, b, c, d, e, f = args
    n = b & 63
    if name in {"edge_adc_flags", "edge_sbb_flags"}:
        carry = c & 1
        if name == "edge_adc_flags":
            raw = a + b + carry
            signed_raw = common.signed(a, 64) + common.signed(b, 64) + carry
            cf = raw > MASK
        else:
            raw = a - b - carry
            signed_raw = common.signed(a, 64) - common.signed(b, 64) - carry
            cf = raw < 0
        of = not -(1 << 63) <= signed_raw < (1 << 63)
        value = (raw & MASK) ^ (int(of) << 63) ^ (int(cf) << 62)
    elif name == "edge_partial_bytes":
        value = (a & ~0xffff) | ((b & 255) << 8) | (c & 255)
    elif name == "edge_partial_word":
        value = (a & ~0xffff) | (b & 0xffff)
    elif name == "edge_cmov32":
        value = (b if c == 0 else a) & 0xffffffff
    elif name == "edge_shift_zero_zf":
        raw = (a << n) & MASK
        zf = (e == c) if n == 0 else raw == 0
        value = raw ^ int(zf)
    elif name == "edge_shift_zero_cf":
        raw = a >> n
        cf = (e < c) if n == 0 else bool((a >> (n - 1)) & 1)
        value = raw ^ int(cf)
    elif name == "edge_sar64":
        value = common.signed(a, 64) >> n
    elif name == "edge_rotate8_cf":
        count = b & 31
        count_mod = count % 8
        raw = a & 255
        if count_mod:
            raw = ((raw << count_mod) | (raw >> (8 - count_mod))) & 255
        # Data uses count modulo eight, but CF uses nonzero masked count.
        # ROL8 by eight leaves data unchanged and still sets CF to its low bit.
        cf = (e < c) if count == 0 else bool(raw & 1)
        value = raw | (int(cf) << 8)
    elif name == "edge_rotate64_cf":
        raw = a if n == 0 else ((a >> n) | (a << (64 - n))) & MASK
        cf = (e < c) if n == 0 else bool(raw >> 63)
        value = raw ^ int(cf)
    elif name == "edge_shift8_value":
        value = ((a & 255) << (b & 31)) & 255
    elif name == "edge_imul_flags":
        raw = common.signed(a, 64) * common.signed(b, 64)
        overflow = not -(1 << 63) <= raw < (1 << 63)
        value = (raw & MASK) ^ (int(overflow) << 63) ^ (int(overflow) << 62)
    elif name == "edge_push_pop_unknown":
        value = a
    elif name == "edge_sbb_unknown_self":
        value = MASK if b < a else 0
    elif name == "edge_inc_preserves_cf":
        value = ((c + 1) & MASK) ^ int(b < a)
    elif name == "edge_sign8_to32":
        value = common.signed(a, 8) & 0xffffffff
    elif name == "edge_sign32_to64":
        value = common.signed(a, 32)
    else:
        raise ValueError(name)
    return value & MASK


def run(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name in ("logs", "source-snapshot", "decompilations", "generated", "candidate"):
        (output / name).mkdir()
    source = Path(__file__).with_name("instruction-edges.S")
    shutil.copy2(source, output / "source-snapshot/instruction-edges.S")
    shutil.copy2(__file__, output / "source-snapshot/instruction_edges.py")
    shutil.copy2(common.__file__, output / "source-snapshot/validate.py")
    cli = Path(args.cli).resolve()
    candidate = output / "candidate/rust-ghidra"
    shutil.copy2(cli, candidate)
    provenance = {"cli": common.digest(cli), "candidate": common.digest(candidate),
                  "sources": [common.digest(source), common.digest(Path(__file__)), common.digest(Path(common.__file__))]}
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    commands = common.Commands(output)
    config = {"input_seed": 0x8a3d5162, "random_input_count": 256}
    vectors = common.inputs(config)
    # Explicit byte/word rotate and masked-count boundaries supplement the
    # shared integer boundaries, before observing any candidate execution.
    for count in (0, 1, 2, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31, 32, 33, 63, 64, 65, 255):
        for a in (0, 1, 0x80, 0xff, 0x8000000000000000, MASK):
            for carry in (0, 1):
                vectors.append([a, count, 1, 0, 0 if carry else 1, 0])
    vectors = [list(case) for case in dict.fromkeys(map(tuple, vectors))]
    (output / "inputs.json").write_text(json.dumps(vectors) + "\n")
    (output / "selection.json").write_text(json.dumps({"supported": SUPPORTED, "guards": GUARDS}, indent=2) + "\n")
    original = output / "original.so"
    compilation = commands.run("compile-original", [args.cc, "-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none",
        str(output / "source-snapshot/instruction-edges.S"), "-o", str(original)])
    cases = []
    if not common.successful(compilation):
        (output / "results.json").write_text(json.dumps({"status": "failed", "compile": compilation}, indent=2) + "\n")
        return 1
    for name in SUPPORTED + GUARDS:
        case = {"function": name, "guard": name in GUARDS}
        cases.append(case)
        directory = output / "decompilations" / name
        invocation = commands.run(f"decompile-{name}", [str(candidate), "decompile", str(original), "--function", name, "--output", str(directory)])
        manifest_path = directory / "manifest.json"
        if not manifest_path.is_file():
            case["status"] = "missing_manifest"
            continue
        manifest = json.loads(manifest_path.read_text())
        source_c = common.generated_source(manifest, directory)
        rejected = common.manifest_status(manifest) in {"unsupported", "error", "failed", "rejected", "invalid"}
        if rejected:
            case["status"] = "guard_rejected" if name in GUARDS and invocation.get("returncode") not in (0, None) and not source_c.exists() else "unexpected_rejection"
            continue
        if not common.successful(invocation) or common.manifest_status(manifest) != "ok" or not source_c.is_file():
            case["status"] = "inconsistent_success"
            continue
        generated = output / "generated" / f"{name}.so"
        compiled = commands.run(f"compile-generated-{name}", [args.cc, "-std=c11", "-O2", "-shared", "-fPIC", "-nostdlib",
            "-fno-stack-protector", "-Wl,--build-id=none", "-Werror=implicit-function-declaration", str(source_c), "-o", str(generated)])
        if not common.successful(compiled):
            case["status"] = "compile_error"
            continue
        generated_name = manifest.get("generated_function", name)
        if name in GUARDS:
            probe = commands.run(f"guard-generated-{name}", [sys.executable, common.__file__, "--worker"], timeout=5,
                payload={"library": str(generated), "function": generated_name, "inputs": [[1, 2, 3, 4, 5, 6]]})
            # Explicit SIGABRT, not timeout/segfault/any arbitrary failure.
            case.update(status="guard_aborted" if probe.get("returncode") == -6 and not probe["timed_out"] else "guard_failed", execution=probe)
            continue
        expected = [oracle(name, vector) for vector in vectors]
        mismatches = []
        case["status"] = "semantic_match"
        for arm, library, function in (("original", original, name), ("generated", generated, generated_name)):
            executed = commands.run(f"execute-{arm}-{name}", [sys.executable, common.__file__, "--worker"], timeout=5,
                payload={"library": str(library), "function": function, "inputs": vectors})
            if not common.successful(executed):
                case.update(status=f"{arm}_execution_error", execution=executed)
                break
            actual = json.loads(Path(executed["stdout"]).read_text())["outputs"]
            if len(actual) != len(expected):
                mismatches.append({"arm": arm, "error": "result_count", "actual": len(actual), "expected": len(expected)})
            mismatches.extend({"arm": arm, "index": i, "input": vectors[i], "expected": wanted, "actual": got}
                for i, (wanted, got) in enumerate(zip(expected, actual)) if got != wanted)
        if mismatches:
            target = output / "generated" / f"{name}-mismatches.json"
            target.write_text(json.dumps(mismatches, indent=2) + "\n")
            case.update(status="semantic_mismatch", mismatches=str(target), mismatch_count=len(mismatches))
        case["vectors"] = len(vectors)
    counts = {}
    for case in cases:
        counts[case["status"]] = counts.get(case["status"], 0) + 1
    passed = counts.get("semantic_match", 0) == len(SUPPORTED) and sum(counts.get(key, 0) for key in ("guard_rejected", "guard_aborted")) == len(GUARDS)
    result = {"status": "passed" if passed else "failed", "counts": counts, "vectors": len(vectors), "cases": cases,
              "commands": commands.count, "artifacts": [common.digest(path) for path in [original, *sorted((output / "generated").glob("*.so"))]]}
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "counts", "vectors")}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cc", default="gcc")
    raise SystemExit(run(parser.parse_args()))
