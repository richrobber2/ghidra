#!/usr/bin/env python3
"""Reproduce compatible ELF-header constructor benchmarks, with raw observations.

This measures neither ElfHeader.parse(), binary I/O throughput, nor decompilation.
Linux wait4 supplies per-process peak RSS without requiring GNU time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "bench"
GHIDRA = Path("/workspace/ghidra")
JAVA = Path("/workspace/toolchains/jdk-25.0.4.1/bin")
MASK64 = (1 << 64) - 1


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def output(command: list[str], env=None) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True, env=env)
    return (result.stdout + result.stderr).strip()


def prepare_corpus() -> tuple[list[Path], list[dict]]:
    corpus = BENCH / "corpus"
    corpus.mkdir(exist_ok=True)
    sources = [(ROOT / "fixtures" / f"{kind}-{bits}-{endian}.elf", "synthetic-header")
               for kind in ("valid", "extended") for bits in (32, 64) for endian in ("le", "be")]
    for candidate in ("/bin/true", "/bin/ls", "/bin/bash", "/usr/bin/python3"):
        path = Path(candidate)
        if path.is_file() and path.read_bytes()[:4] == b"\x7fELF":
            sources.append((path, "real-elf-header"))
    paths, manifest = [], []
    for number, (source, kind) in enumerate(sources):
        destination = corpus / f"{number:02d}-{source.name}"
        shutil.copyfile(source, destination)
        paths.append(destination)
        manifest.append({"source": str(source.resolve()), "path": str(destination.relative_to(ROOT)),
                         "kind": kind, "bytes": destination.stat().st_size, "sha256": sha256(destination)})
    (BENCH / "corpus-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return paths, manifest


def prepare_programs() -> tuple[dict[str, list[str]], dict]:
    jars = sorted(GHIDRA.glob("Ghidra/**/build/libs/*.jar"))
    jars += [Path(line.strip()) for line in (GHIDRA / "build/libraryDependencies.txt").read_text().splitlines()
             if line.strip().endswith(".jar") and Path(line.strip()).is_file()]
    classpath = os.pathsep.join(map(str, dict.fromkeys(jars)))
    classes = BENCH / "classes"
    classes.mkdir(exist_ok=True)
    subprocess.run([str(JAVA / "javac"), "-cp", classpath, "-d", str(classes),
                    str(BENCH / "ElfHeaderBench.java")], check=True)
    env = dict(os.environ)
    env["CARGO_HOME"] = "/workspace/toolchains/rust/cargo"
    env["RUSTUP_HOME"] = "/workspace/toolchains/rust/rustup"
    env["PATH"] = env["CARGO_HOME"] + "/bin:" + env["PATH"]
    cargo = env["CARGO_HOME"] + "/bin/cargo"
    programs = {"java": [str(JAVA / "java"), "-Xms64m", "-Xmx256m", "-cp",
                          str(classes) + os.pathsep + classpath, "ElfHeaderBench"]}
    builds = []
    for name, profile, flags in (("rust-release", "release", ""),
                                 ("rust-max", "max", ""),
                                 ("rust-max-native", "max", "-C target-cpu=native")):
        build_env = dict(env)
        build_env["CARGO_TARGET_DIR"] = str(BENCH / "targets" / name)
        build_env["RUSTFLAGS"] = flags
        build_env.pop("CARGO_ENCODED_RUSTFLAGS", None)
        command = [cargo, "build", "--manifest-path", str(ROOT / "Cargo.toml"), "--offline", "--locked",
                   "--profile", profile, "--bin", "header-bench"]
        subprocess.run(command, env=build_env, check=True)
        programs[name] = [str(Path(build_env["CARGO_TARGET_DIR"]) / profile / "header-bench")]
        builds.append({"variant": name, "command": command, "RUSTFLAGS": flags,
                       "executable_sha256": sha256(Path(programs[name][0]))})
    return programs, {"builds": builds, "java_version": output([str(JAVA / "java"), "-version"]),
                      "rustc_version": output([env["CARGO_HOME"] + "/bin/rustc", "-Vv"], env=env),
                      "java_heap_options": ["-Xms64m", "-Xmx256m"]}


def launch(command: list[str], cpu: int, timeout: int = 60) -> dict:
    # File-backed output avoids pipe deadlocks while wait4 collects this child's RSS.
    # timeout forks and monitors the benchmark; wait4 includes its reaped descendants.
    wrapped = ["taskset", "--cpu-list", str(cpu), "timeout", "--signal=KILL", str(timeout), *command]
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        start = time.perf_counter_ns()
        child = subprocess.Popen(wrapped, stdout=stdout, stderr=stderr)
        _, status, usage = os.wait4(child.pid, 0)
        elapsed = time.perf_counter_ns() - start
        child.returncode = os.waitstatus_to_exitcode(status)
        stdout.seek(0)
        stderr.seek(0)
        out = stdout.read().decode()
        err = stderr.read().decode()
    if child.returncode != 0:
        raise RuntimeError(f"Benchmark process failed ({child.returncode}): {err}\n{out}")
    return {"process_elapsed_ns": elapsed, "process_peak_rss_kib": usage.ru_maxrss,
            "process_user_seconds": usage.ru_utime, "process_system_seconds": usage.ru_stime,
            "stderr": err, "data": json.loads(out)}


def validate(record: dict, reference: dict, corpus_size: int) -> None:
    data = record["data"]
    assert data["digests"] == reference["digests"], "Per-file normalized header digest mismatch"
    assert data["corpus_checksum"] == reference["corpus_checksum"]
    checksum = int(reference["corpus_checksum"])
    for sample in data["samples"]:
        assert sample["parses"] == sample["passes"] * corpus_size
        assert int(sample["checksum"]) == (sample["passes"] * checksum) & MASK64
        sample["ns_per_header"] = sample["elapsed_ns"] / sample["parses"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true", help="Build and compare per-file digests; skip warm benchmarks")
    parser.add_argument("--processes", type=int, default=3)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--warmup-ms", type=int, default=10000)
    parser.add_argument("--sample-ms", type=int, default=500)
    parser.add_argument("--cpu", type=int, default=min(os.sched_getaffinity(0)))
    args = parser.parse_args()
    if min(args.processes, args.samples, args.warmup_ms, args.sample_ms) <= 0:
        parser.error("processes, samples, warmup-ms and sample-ms must be positive")
    if args.cpu not in os.sched_getaffinity(0):
        parser.error("requested CPU is outside the current affinity mask")
    paths, manifest = prepare_corpus()
    programs, toolchains = prepare_programs()
    cpu_info = Path("/proc/cpuinfo").read_text()
    cpu_model = next((line.split(":", 1)[1].strip() for line in cpu_info.splitlines()
                      if line.startswith("model name")), "unknown")
    metadata = {"time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "ghidra_commit": output(["git", "-C", str(GHIDRA), "rev-parse", "HEAD"]),
                "platform": platform.platform(), "cpu_model": cpu_model, "pinned_cpu": args.cpu,
                "allowed_cpus": sorted(os.sched_getaffinity(0)), "load_average_start": os.getloadavg(),
                "parameters": vars(args), "toolchains": toolchains, "corpus": manifest,
                "source_sha256": {str(path.relative_to(ROOT)): sha256(path)
                                   for path in [ROOT / "Cargo.toml", *sorted((ROOT / "src").glob("*.rs")),
                                                BENCH / "header_bench.rs", BENCH / "ElfHeaderBench.java", Path(__file__)]},
                "measurement": "Preloaded ELF header constructor plus normalized field digest; no ElfHeader.parse(), I/O, analysis, or decompilation in timed loops.",
                "rss_scope": "Reported summary uses each benchmark process's /proc/self/status VmHWM after timing: process peak RSS including runtime, preload, warmup and samples, not parser allocation counts. Raw process_peak_rss_kib uses wait4's process-tree high-water maximum including launcher; that value may have an inherited launcher floor and is not used in summaries.",
                "startup_scope": "Parent-observed process launch through exit, including taskset/timeout, runtime startup, file preload, one parse per input, JSON output; warm filesystem cache, not cold disk startup.",
                "native_portability": "rust-max-native uses target-cpu=native and is specific to the measured host CPU.",
                "harness_limitations": "Custom harness, not JMH. Synthetic and real headers remain cache-resident; all files have equal weight. No statement about complete ELF loading or Ghidra analysis speed."}
    results = {"metadata": metadata, "startup": {}, "steady": {name: [] for name in programs}}
    reference = None
    for name, command in programs.items():
        records = []
        for _ in range(1 if args.prepare_only else args.processes):
            record = launch([*command, "0", "0", "0", *map(str, paths)], args.cpu)
            if reference is None:
                reference = record["data"]
            validate(record, reference, len(paths))
            records.append(record)
        results["startup"][name] = records
    print(f"PASS: {len(paths)} benchmark headers have matching Java/Rust normalized-field digests", flush=True)
    if not args.prepare_only:
        # Rotate order between independent process repetitions to spread thermal/time effects.
        names = list(programs)
        for repetition in range(args.processes):
            order = names[repetition % len(names):] + names[:repetition % len(names)]
            for name in order:
                record = launch([*programs[name], str(args.warmup_ms), str(args.sample_ms), str(args.samples),
                                 *map(str, paths)], args.cpu,
                                timeout=max(60, (args.warmup_ms + args.sample_ms * args.samples) // 1000 + 30))
                validate(record, reference, len(paths))
                record["process_repetition"] = repetition
                results["steady"][name].append(record)
                median = statistics.median(sample["ns_per_header"] for sample in record["data"]["samples"])
                print(f"{name} process {repetition + 1}: {median:.2f} ns/header (sample median)", flush=True)
        summary = {}
        for name in programs:
            process_medians = [statistics.median(sample["ns_per_header"] for sample in record["data"]["samples"])
                               for record in results["steady"][name]]
            summary[name] = {"process_medians_ns_per_header": process_medians,
                             "median_ns_per_header": statistics.median(process_medians),
                             "min_process_median_ns_per_header": min(process_medians),
                             "max_process_median_ns_per_header": max(process_medians),
                             "median_startup_ms": statistics.median(record["process_elapsed_ns"] / 1e6
                                                                    for record in results["startup"][name]),
                             "median_whole_process_peak_rss_kib": statistics.median(record["data"]["process_vm_hwm_kib"]
                                                                                    for record in results["steady"][name])}
        for row in summary.values():
            row["java_over_variant_median_ratio"] = summary["java"]["median_ns_per_header"] / row["median_ns_per_header"]
        results["summary"] = summary
    metadata["load_average_end"] = os.getloadavg()
    destination = BENCH / ("preflight.json" if args.prepare_only else "results.json")
    destination.write_text(json.dumps(results, indent=2) + "\n")
    print(f"Saved {destination}", flush=True)


if __name__ == "__main__":
    main()
