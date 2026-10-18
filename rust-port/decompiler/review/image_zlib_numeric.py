#!/usr/bin/env python3
"""Independent numeric gate for three real zlib CRC-combination functions.

Run in an exclusive heavy-work slot. The installed zlib 1.3.1 input and native
Rust CLI are frozen before decompilation. Generated C and original zlib execute
only in short-lived resource-limited workers. This is not a general sandbox.

The CRC combine oracle uses binascii.crc32 on actual bounded concatenated byte
strings. The generator/operator oracle instead uses ordinary polynomial long
division and exponentiation in GF(2)[x]/(0x104c11db7), followed by coefficient
bit reversal. It does not use zlib's table, reflected multiply loop, or native
results to compute expected values. Huge lengths test operators only; no huge
byte strings or concatenation-correctness claims are fabricated.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
from pathlib import Path
import shutil
import sys

import validate

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = Path("/usr/lib/x86_64-linux-gnu/libz.so.1.3.1")
U32 = (1 << 32) - 1
MASK = (1 << 64) - 1
POLYNOMIAL = 0x104C11DB7
FUNCTIONS = ("crc32_combine64", "crc32_combine_gen64", "crc32_combine_op")
DATA_LENGTHS = (0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 257, 1024, 4096)
GEN_LENGTHS = (0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65,
               127, 128, 255, 256, 257, 1023, 1024, 4095, 4096, 65535, 65536,
               (1 << 20) - 1, 1 << 20, (1 << 31) - 1, 1 << 31, (1 << 31) + 1,
               (1 << 32) - 1, 1 << 32, (1 << 32) + 1, (1 << 63) - 2, (1 << 63) - 1)


def reverse32(value: int) -> int:
    """Convert coefficient order, without changing the represented polynomial."""
    return int(f"{value & U32:032b}"[::-1], 2)


def polynomial_remainder(value: int) -> int:
    """Ordinary GF(2) polynomial long division; subtraction is coefficient XOR."""
    while value.bit_length() > 32:
        value ^= POLYNOMIAL << (value.bit_length() - 33)
    return value


def polynomial_multiply(left: int, right: int) -> int:
    """Carryless product, then a separate long-division reduction."""
    product = 0
    for power in range(right.bit_length()):
        if right & (1 << power):
            product ^= left << power
    return polynomial_remainder(product)


def generator(length: int) -> int:
    """The reflected representation of x**(8*length) modulo IEEE CRC32 P(x)."""
    if not 0 <= length < (1 << 63):
        raise ValueError("generator length must be a nonnegative signed-64 value")
    exponent, base, result = length * 8, 2, 1
    while exponent:
        if exponent & 1:
            result = polynomial_multiply(result, base)
        base = polynomial_multiply(base, base)
        exponent >>= 1
    return reverse32(result)


def combine_operator(crc1: int, crc2: int, operator: int) -> int:
    return reverse32(polynomial_multiply(reverse32(operator), reverse32(crc1))) ^ crc2


def make_data(length: int, seed: int) -> bytes:
    return bytes((((index * index + 17 * index + seed * 29) ^ (index >> 3)) & 255)
                 for index in range(length))


def fixed_inputs() -> dict:
    # Elementary identities establish the representation explicitly, rather
    # than learning it from the original library's answers.
    if (generator(0) != 0x80000000 or generator(1) != 0x00800000
            or polynomial_remainder(1 << 32) != 0x04C11DB7):
        raise ValueError("polynomial representation self-check failed")
    buffers, data = [], {}
    for tag, seed in (("left", 0x25), ("right", 0xB7)):
        for length in DATA_LENGTHS:
            block = make_data(length, seed)
            key = f"{tag}-{length}"
            data[key] = block
            buffers.append({"id": key, "length": length, "seed": seed,
                            "bytes_hex": block.hex(), "sha256": hashlib.sha256(block).hexdigest(),
                            "crc32": binascii.crc32(block) & U32})
    cases = {name: {"vectors": [], "expected": [], "metadata": []} for name in FUNCTIONS}
    for left_length in DATA_LENGTHS:
        for right_length in DATA_LENGTHS:
            left_id, right_id = f"left-{left_length}", f"right-{right_length}"
            left, right = data[left_id], data[right_id]
            crc1, crc2 = binascii.crc32(left) & U32, binascii.crc32(right) & U32
            wanted = binascii.crc32(left + right) & U32
            operator = generator(right_length)
            algebraic = combine_operator(crc1, crc2, operator)
            if algebraic != wanted:
                raise ValueError(f"independent polynomial/concatenation oracle disagreement for {left_id}, {right_id}")
            metadata = {"left_buffer": left_id, "right_buffer": right_id,
                        "oracle": "binascii.crc32(actual left+right bytes)", "length2": right_length}
            cases[FUNCTIONS[0]]["vectors"].append([crc1, crc2, right_length, 0x123456789ABCDEF0, MASK, 37])
            cases[FUNCTIONS[0]]["expected"].append(wanted)
            cases[FUNCTIONS[0]]["metadata"].append(metadata)
            cases[FUNCTIONS[2]]["vectors"].append([crc1, crc2, operator, 0x123456789ABCDEF0, MASK, 37])
            cases[FUNCTIONS[2]]["expected"].append(algebraic)
            cases[FUNCTIONS[2]]["metadata"].append({**metadata, "oracle": "ordinary polynomial multiplication, cross-checked against actual concatenated bytes"})
    crc_pairs = ((0, 0), (U32, U32), (0, U32), (U32, 0), (1, 2), (2, 1),
                 (0x80000000, 0x7FFFFFFF), (0x7FFFFFFF, 0x80000000),
                 (0xDEADBEEF, 0x01234567), (0x01234567, 0xDEADBEEF))
    for length in GEN_LENGTHS:
        operator = generator(length)
        if operator == 0:
            raise ValueError("x is a unit modulo a polynomial with constant coefficient 1; its powers cannot be zero")
        cases[FUNCTIONS[1]]["vectors"].append([length, MASK, 0x123456789ABCDEF0, 7, 11, 13])
        cases[FUNCTIONS[1]]["expected"].append(operator)
        cases[FUNCTIONS[1]]["metadata"].append({"length": length, "oracle": "reverse32(x**(8*length) modulo 0x104c11db7)",
                                              "actual_concatenation_test": False})
        for crc1, crc2 in crc_pairs:
            cases[FUNCTIONS[2]]["vectors"].append([crc1, crc2, operator, MASK, 17, 19])
            cases[FUNCTIONS[2]]["expected"].append(combine_operator(crc1, crc2, operator))
            cases[FUNCTIONS[2]]["metadata"].append({"generator_length": length,
                "oracle": "reverse32(mulmod(reverse32(operator),reverse32(crc1))) XOR crc2",
                "actual_concatenation_test": False})
    return {"schema": 1, "polynomial_hex": hex(POLYNOMIAL),
            "representation": "ordinary coefficient bit k denotes x^k; reverse32 converts zlib reflected representation",
            "identity_operator_hex": "0x80000000", "one_byte_operator_hex": "0x00800000",
            "domain": "32-bit CRCs; nonnegative signed-64 lengths; op is generated from a valid length, never arbitrary zero",
            "buffers": buffers, "functions": cases}


def freeze(source: Path, target: Path, provenance: dict) -> None:
    original = validate.digest(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    frozen = validate.digest(target)
    if original["sha256"] != frozen["sha256"]:
        raise RuntimeError(f"source changed during snapshot: {source}")
    provenance["sources"].append({"original": original, "frozen": frozen})


def outputs(record: dict, count: int) -> list[int]:
    if not validate.successful(record):
        raise ValueError("worker did not exit successfully")
    values = json.loads(Path(record["stdout"]).read_text())["outputs"]
    if (not isinstance(values, list) or len(values) != count
            or any(type(value) is not int or not 0 <= value <= U32 for value in values)):
        raise ValueError("worker must emit the exact count of 32-bit CRC/operator values")
    return values


def run(args: argparse.Namespace) -> int:
    output, cli = Path(args.output).resolve(), Path(args.cli).resolve()
    if not cli.is_file() or not LIBRARY.is_file():
        raise SystemExit(f"required CLI/library missing: {cli}, {LIBRARY}")
    output.mkdir(parents=True, exist_ok=False)
    for directory in ("logs", "source-snapshot", "candidate", "input", "decompilations", "generated"):
        (output / directory).mkdir()
    provenance = {"cli": validate.digest(cli), "library": validate.digest(LIBRARY), "sources": [],
                  "python": validate.digest(Path(sys.executable).resolve()), "tools": {},
                  "oracle_contract": "independent ordinary-polynomial algebra and actual-byte binascii CRC; no original-library answers feed expected values"}
    candidate, library = output / "candidate/rust-ghidra", output / "input/libz.so.1.3.1"
    shutil.copy2(cli, candidate)
    shutil.copy2(LIBRARY, library)
    provenance["frozen_cli"], provenance["frozen_library"] = validate.digest(candidate), validate.digest(library)
    for original, frozen in (("cli", "frozen_cli"), ("library", "frozen_library")):
        if provenance[original]["sha256"] != provenance[frozen]["sha256"]:
            raise RuntimeError(f"{original} changed while copying")
    for source in (Path(__file__).resolve(), Path(validate.__file__).resolve(),
                   ROOT / "Cargo.toml", ROOT / "Cargo.lock", *sorted((ROOT / "src").glob("*.rs")),
                   *sorted((ROOT / "src").glob("*.h"))):
        freeze(source, output / "source-snapshot" / source.relative_to(ROOT), provenance)
    for label, source in (("ghidra-elf", ROOT.parent / "src/lib.rs"),
                          ("ghidra-elf-segments", ROOT.parent / "program-headers/src/lib.rs"),
                          ("installed-zlib-header", Path("/usr/include/zlib.h"))):
        freeze(source, output / "source-snapshot/dependencies" / label / source.name, provenance)
    module_path = getattr(binascii, "__file__", None)
    if module_path:
        provenance["binascii_module"] = validate.digest(Path(module_path).resolve())
    for name in (args.cc, "readelf", "objdump"):
        executable = shutil.which(name)
        if executable:
            provenance["tools"][name] = validate.digest(Path(executable).resolve())
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    fixed = fixed_inputs()
    (output / "inputs.json").write_text(json.dumps(fixed, indent=2) + "\n")
    commands = validate.Commands(output)
    cases, errors = [], []
    summary = {"schema": 1, "status": "running", "scope": "three real zlib CRC integer functions; immutable-image numeric validation only",
               "functions_expected": list(FUNCTIONS), "cases": cases, "errors": errors,
               "oracle_notes": "combine64 uses actual bounded concatenations; generator/operator huge-length cases use polynomial algebra only",
               "calling_convention": "x86-64 SysV six-u64 worker; actual zlib signatures use one or three arguments, surplus registers ignored",
               "performance_claim": None}
    try:
        version = commands.run("compiler-version", [args.cc, "--version"])
        if not validate.successful(version):
            errors.append({"stage": "compiler_version", "command": version})
        symbols = commands.run("symbols", ["readelf", "--wide", "--symbols", str(library)])
        if not validate.successful(symbols):
            errors.append({"stage": "symbols", "command": symbols})
        for name in FUNCTIONS:
            inputs, wanted = fixed["functions"][name]["vectors"], fixed["functions"][name]["expected"]
            case = {"function": name, "status": "running", "vectors": len(inputs), "expected": "semantic_match"}
            cases.append(case)
            evidence = commands.run(f"instructions-{name}", ["objdump", "-d", f"--disassemble={name}", str(library)])
            if not validate.successful(evidence):
                case.update(status="instruction_evidence_error", command=evidence)
                continue
            directory = output / "decompilations" / name
            invocation = commands.run(f"decompile-{name}", [str(candidate), "decompile", str(library),
                "--function", name, "--return", "u64", "--output", str(directory)], timeout=args.decompile_timeout)
            case["decompile_command"] = invocation
            manifest_path = directory / "manifest.json"
            if invocation["timed_out"] or not manifest_path.is_file():
                case["status"] = "decompile_timeout" if invocation["timed_out"] else "missing_manifest"
                continue
            try:
                manifest = json.loads(manifest_path.read_text())
                if not isinstance(manifest, dict):
                    raise ValueError("manifest must be an object")
                source = validate.generated_source(manifest, directory)
                if (not validate.successful(invocation) or validate.manifest_status(manifest) != "ok"
                        or manifest.get("backend") != "native-rust" or manifest.get("guarded") is not True
                        or manifest.get("return_kind") != "u64" or not source.is_file()
                        or not isinstance(manifest.get("generated_function"), str)
                        or not manifest["generated_function"].isidentifier()):
                    raise ValueError(f"expected guarded native-Rust u64 artifact; status={manifest.get('status')}, error={manifest.get('error')}")
                image_objects = manifest.get("image_objects")
                if not isinstance(image_objects, list) or (name != "crc32_combine_op" and not image_objects):
                    raise ValueError("generator/combine64 must retain nonempty image-object provenance")
                case.update(manifest=str(manifest_path), image_objects=image_objects)
            except (ValueError, KeyError, TypeError, OSError) as exc:
                case.update(status="invalid_or_unsupported_manifest", error=str(exc))
                continue
            generated = output / "generated" / f"{name}.so"
            compilation = commands.run(f"compile-{name}", [args.cc, "-std=c11", "-O2", "-shared", "-fPIC",
                "-nostdlib", "-fno-stack-protector", "-Wl,--build-id=none", "-Werror=implicit-function-declaration",
                "-Werror=return-type", "-Werror=shift-count-negative", "-Werror=shift-count-overflow",
                str(source), "-o", str(generated)])
            case["compile_command"] = compilation
            if not validate.successful(compilation):
                case["status"] = "generated_compile_error"
                continue
            actual = {}
            for arm, path, function in (("native_zlib", library, name),
                                        ("generated_c", generated, manifest["generated_function"])):
                invocation = commands.run(f"execute-{arm}-{name}", [sys.executable,
                    str(output / "source-snapshot/review/validate.py"), "--worker"], timeout=args.worker_timeout,
                    payload={"library": str(path), "function": function, "inputs": inputs})
                case[f"{arm}_command"] = invocation
                try:
                    actual[arm] = outputs(invocation, len(inputs))
                except (ValueError, KeyError, TypeError, OSError) as exc:
                    case.update(status=f"{arm}_execution_error", error=str(exc))
                    break
            if case["status"] != "running":
                continue
            mismatches = [{"arm": arm, "index": index, "input": inputs[index], "expected": expected, "actual": observed}
                          for arm, values in actual.items() for index, (expected, observed) in enumerate(zip(wanted, values))
                          if expected != observed]
            case["mismatch_count"] = len(mismatches)
            if mismatches:
                path = output / "generated" / f"{name}-mismatches.json"
                path.write_text(json.dumps(mismatches, indent=2) + "\n")
                case.update(status="semantic_mismatch", mismatches=str(path))
            else:
                case.update(status="semantic_match", comparisons_per_arm=len(wanted), total_comparisons=2 * len(wanted))
    except Exception as exc:
        errors.append({"stage": "runner", "type": type(exc).__name__, "error": str(exc)})
    for label, path in (("cli", cli), ("library", LIBRARY), ("frozen_cli", candidate), ("frozen_library", library)):
        provenance[f"{label}_after"] = validate.digest(path)
        if provenance[label] != provenance[f"{label}_after"]:
            errors.append({"stage": "provenance", "error": f"{label} changed during validation"})
    for source in provenance["sources"]:
        if validate.digest(Path(source["frozen"]["path"])) != source["frozen"]:
            errors.append({"stage": "provenance", "error": f"frozen source changed: {source['frozen']['path']}"})
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    counts = {}
    for case in cases:
        counts[case["status"]] = counts.get(case["status"], 0) + 1
    summary.update(counts=counts, commands=commands.count,
                   artifacts=[validate.digest(path) for path in sorted((output / "generated").glob("*.so"))])
    passed = not errors and counts.get("semantic_match", 0) == len(FUNCTIONS)
    summary["status"] = "passed" if passed else "failed"
    (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"status": summary["status"], "counts": counts,
                      "vectors": {case["function"]: case["vectors"] for case in cases}, "errors": errors}, indent=2))
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--output", required=True, help="new retained directory; existing paths refused")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--decompile-timeout", type=int, default=30)
    parser.add_argument("--worker-timeout", type=int, default=10)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
