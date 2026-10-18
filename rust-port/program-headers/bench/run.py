#!/usr/bin/env python3
"""Frozen, serial benchmark of compatible header + program-table parsing.

Default protocol: three processes/arm, 10 s warmup, five >=500 ms samples.
--smoke is a separate plumbing check, not performance evidence. Every invocation
requires a new result directory and retains failures, binaries, inputs and logs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "bench"
GHIDRA = Path("/workspace/ghidra")
JAVA = Path("/workspace/toolchains/jdk-25.0.4.1/bin")
MASK64 = (1 << 64) - 1
PROTOCOL = {"processes": 3, "warmup_ms": 10_000, "sample_ms": 500, "samples": 5}
SMOKE = {"processes": 1, "warmup_ms": 100, "sample_ms": 50, "samples": 2}


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def synthetic(bits: int, little: bool, count: int, rewrite: bool) -> bytes:
    endian = "<" if little else ">"
    ehsize, phsize, phoff = (64, 56, 128) if bits == 64 else (52, 32, 64)
    length = phoff + count * phsize + 128
    data = bytearray(length)
    data[:16] = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if little else 2, 1, 0, 0]) + bytes(7)
    common = (2, 62 if bits == 64 else 3, 1, 0x401000, phoff, 0, 0,
              ehsize, phsize, count, 64 if bits == 64 else 40, 0, 0)
    struct.pack_into(endian + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"), data, 16, *common)
    sizes = [1 + index % 7 for index in range(count)]
    if rewrite:
        sizes[0] += length - sum(sizes)
    for index, file_size in enumerate(sizes):
        segment_type, flags = 1 + index % 4, (index % 7) + 1
        offset = 0x1000 + index * 0x1000
        vaddr = (0x8000000000400000 if bits == 64 else 0x8040000) + offset
        paddr = vaddr + 16
        mem_size, align = file_size + 16, 0x1000
        fields = (segment_type, flags, offset, vaddr, paddr, file_size, mem_size, align) if bits == 64 else (
            segment_type, offset, vaddr, paddr, file_size, mem_size, flags, align)
        struct.pack_into(endian + ("IIQQQQQQ" if bits == 64 else "IIIIIIII"), data, phoff + index * phsize, *fields)
    return bytes(data)


class Run:
    def __init__(self, directory: Path):
        self.directory = directory
        self.counter = 0
        (directory / "logs").mkdir()

    def event(self, value: dict) -> None:
        with (self.directory / "events.jsonl").open("a") as stream:
            stream.write(json.dumps({"time_utc": utc(), **value}) + "\n")

    def command(self, label: str, command: list[str], *, env: dict | None = None,
                timeout: int = 120, cpu: int | None = None) -> dict:
        self.counter += 1
        stem = f"{self.counter:02d}-{label}"
        stdout_path, stderr_path = (self.directory / "logs" / f"{stem}.{kind}" for kind in ("stdout", "stderr"))
        actual = ["taskset", "--cpu-list", str(cpu), *command] if cpu is not None else command
        self.event({"event": "command_start", "label": label, "command": actual, "timeout_seconds": timeout})
        start = time.perf_counter_ns()
        timed_out = False
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            child = subprocess.Popen(actual, stdout=stdout, stderr=stderr, env=env, start_new_session=True)
            while True:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    break
                if time.perf_counter_ns() - start > timeout * 1_000_000_000:
                    timed_out = True
                    os.killpg(child.pid, signal.SIGKILL)
                    _, status, usage = os.wait4(child.pid, 0)
                    break
                time.sleep(0.025)
            child.returncode = os.waitstatus_to_exitcode(status)
        record = {"label": label, "command": actual, "returncode": child.returncode,
                  "timed_out": timed_out, "elapsed_ns": time.perf_counter_ns() - start,
                  "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
                  "wait4_maxrss_kib": usage.ru_maxrss,
                  "stdout": str(stdout_path.relative_to(self.directory)),
                  "stderr": str(stderr_path.relative_to(self.directory))}
        self.event({"event": "command_end", **record})
        if child.returncode != 0 or timed_out:
            raise RuntimeError(f"{label} failed: returncode={child.returncode}, timeout={timed_out}; see {stderr_path}")
        return record

    def output(self, record: dict) -> str:
        return (self.directory / record["stdout"]).read_text()


def corpus(directory: Path) -> tuple[list[Path], list[dict]]:
    destination = directory / "corpus"
    destination.mkdir()
    paths, manifest = [], []
    for bits in (32, 64):
        for little in (True, False):
            for count in (1, 4, 32, 128):
                name = f"table-{bits}-{'le' if little else 'be'}-{count:03}.elf"
                path = destination / name
                path.write_bytes(synthetic(bits, little, count, False))
                paths.append(path)
                manifest.append({"name": name, "kind": "synthetic-canonical-table", "bits": bits,
                                 "little_endian": little, "count": count, "rewrite": False})
    for bits in (32, 64):
        for little in (True, False):
            name = f"rewrite-{bits}-{'le' if little else 'be'}-004.elf"
            path = destination / name
            path.write_bytes(synthetic(bits, little, 4, True))
            paths.append(path)
            manifest.append({"name": name, "kind": "synthetic-legacy-rewrite", "bits": bits,
                             "little_endian": little, "count": 4, "rewrite": True})
    for name, source in (("real-ls", Path("/bin/ls")), ("real-cat", Path("/bin/cat")),
                         ("real-libz", Path("/usr/lib/x86_64-linux-gnu/libz.so.1.3.1"))):
        resolved = source.resolve(strict=True)
        if resolved.stat().st_size > 64 * 1024 * 1024:
            raise ValueError(f"input exceeds explicit 64 MiB limit: {resolved}")
        path = destination / name
        shutil.copyfile(resolved, path)
        if path.read_bytes()[:4] != b"\x7fELF":
            raise ValueError(f"not ELF: {resolved}")
        paths.append(path)
        manifest.append({"name": name, "kind": "host-elf", "source": str(source), "resolved_source": str(resolved)})
    for path, entry in zip(paths, manifest, strict=True):
        entry.update({"path": str(path.relative_to(directory)), "bytes": path.stat().st_size, "sha256": sha256(path)})
    write_json(directory / "corpus-manifest.json", manifest)
    return paths, manifest


def prepare(run: Run) -> tuple[dict[str, list[str]], dict]:
    jars = sorted(GHIDRA.glob("Ghidra/**/build/libs/*.jar"))
    jars += [Path(line.strip()) for line in (GHIDRA / "build/libraryDependencies.txt").read_text().splitlines()
             if line.strip().endswith(".jar") and Path(line.strip()).is_file()]
    jars = list(dict.fromkeys(jars))
    if not jars:
        raise ValueError("no retained Ghidra jars found")
    classpath = os.pathsep.join(map(str, jars))
    classes = run.directory / "classes"
    classes.mkdir()
    run.command("javac", [str(JAVA / "javac"), "-cp", classpath, "-d", str(classes), str(BENCH / "ElfProgramHeadersBench.java")])
    env = dict(os.environ)
    env.update({"CARGO_HOME": "/workspace/toolchains/rust/cargo", "RUSTUP_HOME": "/workspace/toolchains/rust/rustup",
                "CARGO_TARGET_DIR": str(run.directory / "target"), "RUSTFLAGS": ""})
    env["PATH"] = env["CARGO_HOME"] + "/bin:" + env["PATH"]
    for key in ("CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        env.pop(key, None)
    run.command("cargo-build", [env["CARGO_HOME"] + "/bin/cargo", "build", "--manifest-path", str(ROOT / "Cargo.toml"),
                               "--offline", "--locked", "--release", "--bin", "segments-bench"], env=env)
    executable = run.directory / "target/release/segments-bench"
    java_version = run.command("java-version", [str(JAVA / "java"), "-version"])
    rust_version = run.command("rustc-version", [env["CARGO_HOME"] + "/bin/rustc", "-Vv"], env=env)
    commit = run.command("ghidra-commit", ["git", "-C", str(GHIDRA), "rev-parse", "HEAD"])
    programs = {"java": [str(JAVA / "java"), "-Xms64m", "-Xmx256m", "-cp",
                          str(classes) + os.pathsep + classpath, "ElfProgramHeadersBench"],
                "rust": [str(executable)]}
    return programs, {"java_version": (run.directory / java_version["stderr"]).read_text(),
                      "rustc_version": run.output(rust_version), "ghidra_commit": run.output(commit).strip(),
                      "java_heap_options": ["-Xms64m", "-Xmx256m"], "rust_profile": "portable release opt-level=3; no LTO/target-cpu flags",
                      "rust_executable": str(executable.relative_to(run.directory)), "rust_executable_sha256": sha256(executable),
                      "java_class_sha256": sha256(classes / "ElfProgramHeadersBench.class"),
                      "classpath": [{"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)} for path in jars]}


def source_snapshot(directory: Path) -> dict[str, str]:
    paths = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", *sorted((ROOT / "src").glob("*.rs")),
             BENCH / "ElfProgramHeadersBench.java", BENCH / "segments_bench.rs", BENCH / "audit.py", Path(__file__).resolve(),
             ROOT.parent / "Cargo.toml", ROOT.parent / "Cargo.lock", ROOT.parent / "src/lib.rs",
             GHIDRA / "Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfHeader.java",
             GHIDRA / "Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfProgramHeader.java"]
    hashes = {}
    for path in paths:
        relative = path.relative_to("/workspace")
        target = directory / "source-snapshot" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        hashes[str(path)] = sha256(path)
    return hashes


def validate(data: dict, reference: dict, corpus_size: int, expected_samples: int, minimum_ms: int) -> None:
    if data["digests"] != reference["digests"] or len(data["digests"]) != corpus_size:
        raise ValueError("per-input shared-field digest mismatch")
    if data["corpus_checksum"] != reference["corpus_checksum"]:
        raise ValueError("corpus checksum mismatch")
    if len(data["samples"]) != expected_samples:
        raise ValueError("sample count mismatch")
    checksum = int(reference["corpus_checksum"])
    for sample in data["samples"]:
        if sample["passes"] <= 0 or sample["parses"] != sample["passes"] * corpus_size:
            raise ValueError("invalid pass/parse count")
        if int(sample["checksum"]) != (sample["passes"] * checksum) & MASK64:
            raise ValueError("measured checksum mismatch")
        if sample["elapsed_ns"] < minimum_ms * 1_000_000:
            raise ValueError("sample shorter than fixed minimum")
        sample["ns_per_header_and_table"] = sample["elapsed_ns"] / sample["parses"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True, help="new output directory; existing paths are refused")
    parser.add_argument("--smoke", action="store_true", help="short, separately labeled harness check")
    parser.add_argument("--prepare-only", action="store_true", help="build and verify all per-input digests, without timed samples")
    parser.add_argument("--cpu", type=int, default=min(os.sched_getaffinity(0)))
    args = parser.parse_args()
    if args.cpu not in os.sched_getaffinity(0):
        parser.error("CPU outside current affinity mask")
    result = args.result.resolve()
    result.mkdir(parents=True, exist_ok=False)
    run = Run(result)
    protocol = dict(SMOKE if args.smoke else PROTOCOL)
    records = {"status": "running", "time_utc": utc(), "mode": "preflight" if args.prepare_only else "smoke" if args.smoke else "fixed-production",
               "protocol": protocol, "order": ["java", "rust", "rust", "java", "java", "rust"][:protocol["processes"] * 2],
               "pinned_cpu": args.cpu, "allowed_cpus": sorted(os.sched_getaffinity(0)), "platform": platform.platform(),
               "cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                                  if line.startswith("model name")), "unknown"),
               "load_average_start": os.getloadavg(), "preflight": {}, "steady": {"java": [], "rust": []},
               "scope": "Preloaded compatible ElfHeader constructor + private parseProgramHeaders and shared observable-field digest; no full ElfHeader.parse, file I/O, loading, analysis or decompilation in timed intervals.",
               "limitations": ["Custom harness, not JMH; cache-resident fixed equal-weight corpus.",
                               "Original Java allocates readers/header objects/arrays; Rust uses a borrowed table view and decodes during validation/iteration.",
                               "Cached MethodHandle calls and raw address VarHandle reads are included only in the Java arm; their separate overhead is not isolated.",
                               "Pre-rewrite raw_offset and unexposed rewrite status are excluded from both timed digests and checked by the separate oracle. Effective post-rewrite offsets are included.",
                               "VmHWM/wait4 are retained raw whole-process observations, not allocation counts or reliable true peaks; no memory-savings claim.",
                               "No whole-Ghidra performance claim; timed output normalization and runtime costs belong to this component boundary."]}
    try:
        source_hashes = source_snapshot(result)
        records["source_sha256"] = source_hashes
        paths, manifest = corpus(result)
        records["corpus"] = manifest
        programs, toolchains = prepare(run)
        records["toolchains"] = toolchains
        reference = None
        for name in ("java", "rust"):
            record = run.command(f"preflight-{name}", [*programs[name], "0", "0", "0", *map(str, paths)], cpu=args.cpu)
            data = json.loads(run.output(record))
            if reference is None:
                reference = data
            validate(data, reference, len(paths), 0, 0)
            record["data"] = data
            records["preflight"][name] = record
        records["all_per_input_digests_match"] = True
        print(f"PASS: all {len(paths)} per-input Java/Rust shared-field digests match", flush=True)
        if not args.prepare_only:
            for number, name in enumerate(records["order"]):
                record = run.command(f"steady-{number:02}-{name}", [*programs[name], str(protocol["warmup_ms"]),
                                     str(protocol["sample_ms"]), str(protocol["samples"]), *map(str, paths)],
                                     cpu=args.cpu, timeout=90)
                data = json.loads(run.output(record))
                validate(data, reference, len(paths), protocol["samples"], protocol["sample_ms"])
                record["data"] = data
                record["order_position"] = number
                record["median_ns_per_header_and_table"] = statistics.median(sample["ns_per_header_and_table"] for sample in data["samples"])
                records["steady"][name].append(record)
                print(f"{name} process {len(records['steady'][name])}: {record['median_ns_per_header_and_table']:.2f} ns/header+table", flush=True)
            summary = {}
            for name, observations in records["steady"].items():
                medians = [row["median_ns_per_header_and_table"] for row in observations]
                summary[name] = {"process_sample_medians_ns": medians, "median_ns": statistics.median(medians),
                                 "min_process_median_ns": min(medians), "max_process_median_ns": max(medians)}
            summary["java_over_rust_ratio_of_process_medians"] = summary["java"]["median_ns"] / summary["rust"]["median_ns"]
            records["summary"] = summary
        if any(sha256(Path(path)) != expected for path, expected in source_hashes.items()):
            raise ValueError("source changed during the frozen benchmark run")
        if any(sha256(result / row["path"]) != row["sha256"] for row in manifest):
            raise ValueError("frozen corpus changed during benchmark run")
        if sha256(result / toolchains["rust_executable"]) != toolchains["rust_executable_sha256"]:
            raise ValueError("frozen Rust executable changed during benchmark run")
        if sha256(result / "classes/ElfProgramHeadersBench.class") != toolchains["java_class_sha256"]:
            raise ValueError("frozen Java class changed during benchmark run")
        if any(sha256(Path(row["path"])) != row["sha256"] for row in toolchains["classpath"]):
            raise ValueError("original Java classpath changed during benchmark run")
        records["status"] = "passed"
    except BaseException as error:
        records["status"] = "failed"
        records["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        records["finished_time_utc"] = utc()
        records["load_average_end"] = os.getloadavg()
        write_json(result / "results.json", records)
        print(f"Saved {result / 'results.json'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
