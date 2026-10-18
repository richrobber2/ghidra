#!/usr/bin/env python3
"""Fresh, fixed four-kernel optimized Rust semantic demonstration.

Uses validate.py only for generic command retention, fixed input generation,
manifest validation and execution isolation. Expected values below are
independent formulas for the separate Rust sources. No old C result changes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

import validate

MASK = (1 << 64) - 1
FUNCTIONS = ("rust_arithmetic", "rust_rotate", "rust_branch", "rust_loop")


def expected(name: str, values: list[int]) -> int:
    a, b, c, d, e, f = values
    if name == "rust_arithmetic":
        return ((a + b) * ((c + 37) & MASK) - (d ^ e) + f) & MASK
    if name == "rust_rotate":
        left, right = b & 63, d & 63
        rol = ((a << left) | (a >> ((-left) & 63))) & MASK
        ror = ((c >> right) | (c << ((-right) & 63))) & MASK
        return (((rol + ror) & MASK) ^ e ^ f) & MASK
    if name == "rust_branch":
        return ((c + d) if a < b else (e - f)) & MASK
    if name == "rust_loop":
        value = b
        for n in range((a & 15) + 1, 0, -1):
            value = ((value ^ ((c + n) & MASK)) + d) & MASK
        return value ^ e ^ f
    raise ValueError(name)


def run(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    cli = Path(args.cli).resolve()
    if not cli.is_file():
        raise SystemExit(f"CLI does not exist: {cli}")
    output.mkdir(parents=True, exist_ok=False)
    for directory in ("logs", "source-snapshot", "candidate", "target", "decompilations", "generated"):
        (output / directory).mkdir()
    source = validate.ROOT / "fixtures/rust-kernels.rs"
    provenance = {"cli": validate.digest(cli), "sources": []}
    frozen_cli = output / "candidate/rust-ghidra"
    shutil.copy2(cli, frozen_cli)
    provenance["frozen_cli"] = validate.digest(frozen_cli)
    if provenance["cli"]["sha256"] != provenance["frozen_cli"]["sha256"]:
        raise RuntimeError("candidate changed while being copied")
    for path in (source, Path(__file__).resolve(), Path(validate.__file__).resolve(),
                 validate.ROOT / "fixtures/corpus.json"):
        relative = path.relative_to(validate.ROOT)
        snapshot = output / "source-snapshot" / relative
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, snapshot)
        provenance["sources"].append(validate.digest(path))
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    config = json.loads((validate.ROOT / "fixtures/corpus.json").read_text())
    vectors = validate.inputs(config)
    (output / "inputs.json").write_text(json.dumps(vectors) + "\n")
    commands = validate.Commands(output)
    cases, errors = [], []
    summary = {"schema": 1, "status": "running", "scope": "four portable optimized Rust six-u64 scalar leaf kernels",
               "functions_expected": list(FUNCTIONS), "input_vectors": len(vectors), "cases": cases, "errors": errors,
               "compiler_policy": "rustc edition2024 cdylib opt-level3 debuginfo1 panicabort; no CPU flags or LTO"}
    try:
        commands.run("rustc-version", [args.rustc, "--version", "--verbose"])
        commands.run("gcc-version", [args.cc, "--version"])
        library = output / "target/librust_kernels.so"
        compilation = commands.run("compile-rust", [args.rustc, "--edition=2024", "--crate-type=cdylib",
            "--crate-name=rust_kernels", "-C", "opt-level=3", "-C", "debuginfo=1", "-C", "strip=none",
            "-C", "panic=abort", str(output / "source-snapshot/fixtures/rust-kernels.rs"), "-o", str(library)], timeout=120)
        if not validate.successful(compilation):
            errors.append({"stage": "compile_original", "command": compilation})
        else:
            for name in FUNCTIONS:
                case = {"function": name, "status": "running"}
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
                    regenerated_source = validate.generated_source(manifest, directory)
                except (ValueError, OSError) as exc:
                    case.update(status="invalid_manifest", error=str(exc))
                    continue
                case["manifest"] = str(manifest_path)
                case["reported_status"] = validate.manifest_status(manifest)
                if case["reported_status"] != "ok":
                    case["status"] = "unsupported" if case["reported_status"] == "unsupported" else "decompile_error"
                    continue
                if not validate.successful(invocation) or not regenerated_source.is_file():
                    case["status"] = "inconsistent_success"
                    continue
                regenerated = output / "generated" / f"{name}.so"
                compile_c = commands.run(f"compile-generated-{name}", [args.cc, "-std=c11", "-O2", "-fPIC", "-shared",
                    "-nostdlib", "-fno-stack-protector", "-Wl,--build-id=none", "-Werror=implicit-function-declaration",
                    "-Werror=return-type", "-Werror=shift-count-negative", "-Werror=shift-count-overflow",
                    str(regenerated_source), "-o", str(regenerated)])
                case["compile_command"] = compile_c
                if not validate.successful(compile_c):
                    case["status"] = "generated_c_compile_error"
                    continue
                wanted = [expected(name, vector) for vector in vectors]
                outputs = {}
                for arm, path, function in (("native_rust", library, name),
                                            ("generated_c", regenerated, manifest.get("generated_function", name))):
                    execution = commands.run(f"execute-{arm}-{name}", [sys.executable, str(Path(validate.__file__).resolve()), "--worker"],
                        timeout=config["child_timeout_seconds"], payload={"library": str(path), "function": function, "inputs": vectors})
                    case[f"{arm}_command"] = execution
                    if not validate.successful(execution):
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
                    if len(actual) != len(wanted):
                        mismatches.append({"arm": arm, "error": "wrong result count", "actual": len(actual), "expected": len(wanted)})
                        continue
                    mismatches.extend({"arm": arm, "index": i, "input": vectors[i], "expected": required, "actual": observed}
                                      for i, (required, observed) in enumerate(zip(wanted, actual)) if required != observed)
                case["mismatch_count"] = len(mismatches)
                if mismatches:
                    path = output / "generated" / f"{name}-mismatches.json"
                    path.write_text(json.dumps(mismatches, indent=2) + "\n")
                    case.update(status="semantic_mismatch", mismatches=str(path))
                else:
                    case.update(status="semantic_match", comparisons_per_arm=len(wanted))
    except Exception as exc:
        errors.append({"stage": "runner", "type": type(exc).__name__, "error": str(exc)})
    provenance["cli_after"] = validate.digest(cli)
    if provenance["cli_after"] != provenance["cli"]:
        errors.append({"stage": "provenance", "error": "source CLI changed during validation"})
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    counts = {}
    for case in cases:
        counts[case["status"]] = counts.get(case["status"], 0) + 1
    summary["counts"] = counts
    summary["commands"] = commands.count
    summary["artifacts"] = [validate.digest(path) for directory in ("target", "generated")
                            for path in sorted((output / directory).glob("*.so"))]
    passed = not errors and counts.get("semantic_match", 0) == len(FUNCTIONS)
    summary["status"] = "passed" if passed else "failed"
    (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"status": summary["status"], "counts": counts, "input_vectors": len(vectors)}, indent=2))
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new result directory")
    parser.add_argument("--cli", required=True)
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--decompile-timeout", type=int, default=30)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
