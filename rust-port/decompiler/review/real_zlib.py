#!/usr/bin/env python3
"""Fixed real-library demonstration for the standalone native Rust decompiler.

The input is the installed zlib 1.3.1 shared library, frozen before analysis.
compressBound is checked against a separately written wrapping-u64 formula and
the original library. zlibCompileFlags has only a native-library equivalence
oracle; it is not counted as independent mathematical validation. zlibVersion
must reject its RIP-relative address rather than emit an unrelocated ELF VMA.

Only the trusted installed library and generated C are executed, in the common
resource-limited worker. Six-u64 calls use the x86-64 SysV convention; these two
zlib functions consume respectively one and zero integer arguments, ignoring
the surplus argument registers. This runner is not a general binary sandbox.
No timing, decompiler-wide correctness or whole-library support claim follows.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

import validate

LIBRARY = Path("/usr/lib/x86_64-linux-gnu/libz.so.1.3.1")
MASK = (1 << 64) - 1
FUNCTIONS = ("compressBound", "zlibCompileFlags")
REJECTION = "zlibVersion"


def compress_bound(values: list[int]) -> int:
    """zlib's public bound formula, independently expressed as unsigned u64."""
    a = values[0]
    return (a + (a >> 12) + (a >> 14) + (a >> 25) + 13) & MASK


def read_outputs(record: dict, count: int) -> list[int]:
    payload = json.loads(Path(record["stdout"]).read_text())
    values = payload["outputs"]
    if (not isinstance(values, list) or len(values) != count
            or any(type(value) is not int or not 0 <= value <= MASK for value in values)):
        raise ValueError("worker outputs must be the exact vector count of unsigned-u64 integers")
    return values


def snapshot(source: Path, destination: Path, provenance: dict) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    original = validate.digest(source)
    shutil.copy2(source, destination)
    frozen = validate.digest(destination)
    if original["sha256"] != frozen["sha256"]:
        raise RuntimeError(f"source changed while being copied: {source}")
    provenance["sources"].append({"original": original, "frozen": frozen})


def run(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    cli = Path(args.cli).resolve()
    if not cli.is_file() or not LIBRARY.is_file():
        raise SystemExit(f"required CLI/library is missing: {cli}, {LIBRARY}")
    output.mkdir(parents=True, exist_ok=False)
    for directory in ("logs", "source-snapshot", "candidate", "input", "decompilations", "generated"):
        (output / directory).mkdir()
    provenance = {"cli": validate.digest(cli), "input": validate.digest(LIBRARY), "sources": [],
                  "python": validate.digest(Path(sys.executable).resolve()),
                  "formula": "(a + (a >> 12) + (a >> 14) + (a >> 25) + 13) modulo 2^64",
                  "formula_oracle_function": "compressBound",
                  "native_equivalence_only_function": "zlibCompileFlags"}
    frozen_cli = output / "candidate/rust-ghidra"
    library = output / "input/libz.so.1.3.1"
    shutil.copy2(cli, frozen_cli)
    shutil.copy2(LIBRARY, library)
    provenance["frozen_cli"] = validate.digest(frozen_cli)
    provenance["frozen_input"] = validate.digest(library)
    for original, frozen in (("cli", "frozen_cli"), ("input", "frozen_input")):
        if provenance[original]["sha256"] != provenance[frozen]["sha256"]:
            raise RuntimeError(f"{original} changed while being copied")
    for path in (Path(__file__).resolve(), Path(validate.__file__).resolve(),
                 validate.ROOT / "fixtures/corpus.json", validate.ROOT / "Cargo.toml",
                 validate.ROOT / "Cargo.lock", *sorted((validate.ROOT / "src").glob("*.rs"))):
        snapshot(path, output / "source-snapshot" / path.relative_to(validate.ROOT), provenance)
    for label, source in (("ghidra-elf", validate.ROOT.parent / "src/lib.rs"),
                          ("ghidra-elf-segments", validate.ROOT.parent / "program-headers/src/lib.rs")):
        snapshot(source, output / "source-snapshot/dependencies" / label / "lib.rs", provenance)
    provenance["tools"] = {}
    for name in (args.cc, "readelf", "objdump"):
        executable = shutil.which(name)
        if executable is not None:
            provenance["tools"][name] = validate.digest(Path(executable).resolve())
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    config = json.loads((output / "source-snapshot/fixtures/corpus.json").read_text())
    vectors = validate.inputs(config)
    (output / "inputs.json").write_text(json.dumps(vectors) + "\n")
    worker = output / "source-snapshot/review/validate.py"
    commands = validate.Commands(output)
    cases, errors = [], []
    summary = {"schema": 1, "status": "running", "scope": "two real zlib integer leaf functions and one mandatory global-address rejection",
               "input_vectors": len(vectors), "functions_expected": list(FUNCTIONS),
               "mandatory_rejection": REJECTION, "cases": cases, "errors": errors,
               "oracle_types": {"compressBound": "original installed library plus independent wrapping-u64 formula",
                                "zlibCompileFlags": "original installed library equivalence only"},
               "calling_convention": "x86-64 SysV: six u64 register arguments; original functions ignore surplus arguments"}
    try:
        version = commands.run("compiler-version", [args.cc, "--version"])
        if not validate.successful(version):
            errors.append({"stage": "compiler_version", "command": version})
        for tool, argv in (("symbols", ["readelf", "--wide", "--symbols", str(library)]),
                           ("compress-bound-instructions", ["objdump", "-d", "--disassemble=compressBound", str(library)]),
                           ("compile-flags-instructions", ["objdump", "-d", "--disassemble=zlibCompileFlags", str(library)]),
                           ("version-instructions", ["objdump", "-d", "--disassemble=zlibVersion", str(library)])):
            record = commands.run(tool, argv)
            if not validate.successful(record):
                errors.append({"stage": "input_evidence", "command": record})
        for name in (*FUNCTIONS, REJECTION):
            case = {"function": name, "expected_supported": name in FUNCTIONS, "status": "running"}
            cases.append(case)
            directory = output / "decompilations" / name
            invocation = commands.run(f"decompile-{name}", [str(frozen_cli), "decompile", str(library),
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
                source = validate.generated_source(manifest, directory)
            except (ValueError, OSError) as exc:
                case.update(status="invalid_manifest", error=str(exc))
                continue
            case["manifest"] = str(manifest_path)
            case["reported_status"] = validate.manifest_status(manifest)
            if name == REJECTION:
                reason = manifest.get("error", "")
                if (case["reported_status"] == "unsupported" and invocation.get("returncode") == 1
                        and not source.exists() and isinstance(reason, str)
                        and "RIP-relative" in reason and "relocation" in reason):
                    case.update(status="rejected_as_required", rejection_reason=reason)
                else:
                    case.update(status="unsafe_acceptance_or_invalid_rejection", rejection_reason=reason)
                continue
            if case["reported_status"] != "ok":
                case["status"] = "unsupported_expected_supported" if case["reported_status"] == "unsupported" else "decompile_error"
                continue
            if not validate.successful(invocation) or not source.is_file():
                case["status"] = "inconsistent_success"
                continue
            generated = output / "generated" / f"{name}.so"
            compilation = commands.run(f"compile-generated-{name}", [args.cc, "-std=c11", "-O2", "-fPIC", "-shared",
                "-nostdlib", "-fno-stack-protector", "-Wl,--build-id=none", "-Werror=implicit-function-declaration",
                "-Werror=return-type", "-Werror=shift-count-negative", "-Werror=shift-count-overflow",
                str(source), "-o", str(generated)])
            case["compile_command"] = compilation
            if not validate.successful(compilation):
                case["status"] = "generated_c_compile_error"
                continue
            outputs = {}
            for arm, path, function in (("original_zlib", library, name),
                                        ("generated_c", generated, manifest.get("generated_function", name))):
                execution = commands.run(f"execute-{arm}-{name}", [sys.executable, str(worker), "--worker"],
                    timeout=config["child_timeout_seconds"], payload={"library": str(path), "function": function, "inputs": vectors})
                case[f"{arm}_command"] = execution
                if not validate.successful(execution):
                    case["status"] = f"{arm}_execution_error"
                    break
                try:
                    outputs[arm] = read_outputs(execution, len(vectors))
                except (ValueError, KeyError, TypeError) as exc:
                    case.update(status=f"{arm}_invalid_output", error=str(exc))
                    break
            if case["status"] != "running":
                continue
            mismatches = []
            required = ([compress_bound(vector) for vector in vectors] if name == "compressBound"
                        else outputs["original_zlib"])
            for arm, actual in outputs.items():
                mismatches.extend({"arm": arm, "index": i, "input": vectors[i], "expected": wanted, "actual": observed}
                                  for i, (wanted, observed) in enumerate(zip(required, actual)) if wanted != observed)
            case["mismatch_count"] = len(mismatches)
            if mismatches:
                path = output / "generated" / f"{name}-mismatches.json"
                path.write_text(json.dumps(mismatches, indent=2) + "\n")
                case.update(status="semantic_mismatch", mismatches=str(path))
            else:
                case.update(status="semantic_match", comparisons_per_arm=len(required), oracle_type=summary["oracle_types"][name])

        coverage_dir = output / "decompilations/library-batch"
        coverage_command = commands.run("analyze-library-batch", [str(frozen_cli), "analyze", str(library),
            "--max-functions", "1000", "--output", str(coverage_dir)], timeout=args.analyze_timeout)
        summary["coverage_command"] = coverage_command
        try:
            coverage = json.loads((coverage_dir / "manifest.json").read_text())
            rows = coverage["functions"]
            if not isinstance(rows, list):
                raise ValueError("coverage functions must be an array")
            accepted = sum(row.get("status") == "ok" for row in rows)
            unsupported = sum(row.get("status") == "unsupported" for row in rows)
            total, attempted = coverage["function_count"], coverage["attempted_count"]
            if (coverage_command["timed_out"] or coverage_command.get("returncode") != 1
                    or coverage.get("status") != "partial" or coverage.get("backend") != "native-rust"
                    or any(type(value) is not int for value in (total, attempted))
                    or total < attempted or attempted != len(rows)
                    or accepted != coverage["decompiled_count"] or unsupported != coverage["unsupported_count"]
                    or accepted + unsupported != attempted or accepted < len(FUNCTIONS)
                    or type(coverage.get("truncated")) is not bool
                    or (not coverage["truncated"] and total != attempted)):
                raise ValueError("batch must report consistent partial coverage and explicit per-function statuses")
            summary["coverage"] = {"status": coverage["status"], "inventory_count": total,
                "attempted_count": attempted, "decompiled_count": accepted, "unsupported_count": unsupported,
                "truncated": coverage["truncated"], "manifest": str(coverage_dir / "manifest.json"),
                "interpretation": "bounded observed coverage of this frozen library; unsupported cases are retained, not correctness failures or a whole-library support claim"}
        except (ValueError, KeyError, TypeError, OSError) as exc:
            errors.append({"stage": "coverage", "error": str(exc)})
    except Exception as exc:
        errors.append({"stage": "runner", "type": type(exc).__name__, "error": str(exc)})

    provenance["cli_after"] = validate.digest(cli)
    provenance["input_after"] = validate.digest(LIBRARY)
    provenance["frozen_cli_after"] = validate.digest(frozen_cli)
    provenance["frozen_input_after"] = validate.digest(library)
    for before, after in (("cli", "cli_after"), ("input", "input_after"),
                          ("frozen_cli", "frozen_cli_after"), ("frozen_input", "frozen_input_after")):
        if provenance[before] != provenance[after]:
            errors.append({"stage": "provenance", "error": f"{before} changed during validation"})
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    counts = {}
    for case in cases:
        counts[case["status"]] = counts.get(case["status"], 0) + 1
    summary["counts"] = counts
    summary["commands"] = commands.count
    summary["artifacts"] = [validate.digest(path) for path in sorted((output / "generated").glob("*.so"))]
    passed = (not errors and counts.get("semantic_match", 0) == len(FUNCTIONS)
              and counts.get("rejected_as_required", 0) == 1 and "coverage" in summary)
    summary["status"] = "passed" if passed else "failed"
    (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"status": summary["status"], "counts": counts, "input_vectors": len(vectors),
                      "coverage": summary.get("coverage"), "errors": errors}, indent=2))
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new result directory; existing paths are refused")
    parser.add_argument("--cli", required=True, help="standalone native Rust decompiler binary")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--decompile-timeout", type=int, default=30)
    parser.add_argument("--analyze-timeout", type=int, default=90)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
