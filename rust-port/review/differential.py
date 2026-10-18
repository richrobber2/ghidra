#!/usr/bin/env python3
"""Bounded, deterministic header differential checks against the actual Java class.

Writes only review/. Run without --rust for Java observations, or pass the built
ghidra-elf binary to compare compatible-mode output. This is not a benchmark.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "review"
CASES = REVIEW / "cases"
GHIDRA = Path("/workspace/ghidra")
JAVA = Path("/workspace/toolchains/jdk-25.0.4.1/bin")
KEYS = ("accepted", "class_bits", "header_little_endian", "declared_little_endian",
        "type", "machine", "version", "entry_hex", "phoff_hex", "shoff_hex", "flags",
        "ehsize", "phentsize", "phnum", "shentsize", "shnum", "shstrndx")


def header(bits=64, endian="<", **changes):
    values = dict(type=2, machine=62 if bits == 64 else 3, version=1,
                  entry=0x12345678, phoff=0, shoff=0, flags=0x80000001,
                  ehsize=64 if bits == 64 else 52, phentsize=56 if bits == 64 else 32,
                  phnum=0, shentsize=64 if bits == 64 else 40, shnum=0, shstrndx=0)
    values.update(changes)
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if endian == "<" else 2,
                                1, 0, 0]) + bytes(7)
    return ident + struct.pack(endian + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"),
                               *values.values())


def section(bits=64, endian="<", **changes):
    values = dict(name=0, type=0, flags=0, addr=0, offset=0, size=3,
                  link=1, info=2, addralign=0, entsize=0)
    values.update(changes)
    return struct.pack(endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"),
                       *values.values())


def generate():
    CASES.mkdir(exist_ok=True)
    manifest = []

    def add(name, data, category):
        assert len(data) <= 512, "Keep the oracle corpus small and bounded"
        path = CASES / (name + ".elf")
        path.write_bytes(data)
        manifest.append(dict(file=path.name, category=category, length=len(data),
                             sha256=hashlib.sha256(data).hexdigest()))

    for bits in (32, 64):
        for endian in ("<", ">"):
            stem = f"{bits}-{'le' if endian == '<' else 'be'}"
            base = header(bits, endian)
            for n in range(len(base) + 1):
                add(f"truncate-{stem}-{n:02}", base[:n], "header-truncation")
            for index in (4, 5, 6, 7, 8):
                for val in (0, 1, 2, 3, 127, 128, 255):
                    data = bytearray(base); data[index] = val
                    add(f"ident-{stem}-{index}-{val}", data, "identification")
            for field in ("type", "machine", "ehsize", "phentsize", "phnum", "shentsize", "shnum", "shstrndx"):
                for val in (0, 1, 0x7fff, 0x8000, 0xfeff, 0xff00, 0xffff):
                    add(f"short-{stem}-{field}-{val:04x}", header(bits, endian, **{field: val}), "raw-short")
            for version in (0, 2, 0x01000000, 0x01000001, 0xffffffff):
                add(f"version-{stem}-{version:08x}", header(bits, endian, version=version), "header-version")

            sec = section(bits, endian)
            size = len(base)
            # Prefix cuts expose the phnum-before-shentsize initialization order.
            for n in dict.fromkeys((0, 1, 4, 8, 16, 20, 24, 28, 32, 39, len(sec) - 1, len(sec))):
                if n > len(sec):
                    continue
                for phnum in (0, 0xffff):
                    add(f"section-cut-{stem}-{n}-{phnum}",
                        header(bits, endian, shoff=size, phnum=phnum, shstrndx=0xffff) + sec[:n],
                        "section-zero-truncation")
            for phnum in (0, 0xffff):
                for entsize in (0, 1, len(sec) - 1, len(sec), len(sec) + 1, 0x7fff, 0x8000, 0xffff):
                    add(f"section-size-{stem}-{entsize:04x}-{phnum}",
                        header(bits, endian, shoff=size, phnum=phnum, shentsize=entsize, shstrndx=0xffff) + sec,
                        "signed-section-entry-size")
            for field in ("type", "size", "link", "info"):
                for val in (0, 1, 0x7fffffff, 0x80000000, 0xffffffff):
                    add(f"extended-{stem}-{field}-{val:x}",
                        header(bits, endian, shoff=size, phnum=0xffff, shstrndx=0xffff) + section(bits, endian, **{field: val}),
                        "extended-boundary")
            if bits == 64:
                for val in (0x100000000, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff):
                    add(f"extended-{stem}-size-{val:x}",
                        header(bits, endian, shoff=size, phnum=0xffff, shstrndx=0xffff) + section(bits, endian, size=val),
                        "extended-boundary")
            for offset in (0, 1, size - 1, size, size + 1, 4096, (1 << bits) - 1):
                add(f"offset-{stem}-{offset:x}",
                    header(bits, endian, shoff=offset, phnum=0xffff, shstrndx=0xffff) + sec, "section-offset")
            for kind in (0, 1, 2, 0xffffffff):
                compressed = struct.pack(endian + ("IIQQ" if bits == 64 else "III"),
                                         *([kind, 0, 17, 1] if bits == 64 else [kind, 17, 1]))
                for flags in (0x800, 0x802):
                    data = header(bits, endian, shoff=size, phnum=0xffff, shstrndx=0xffff)
                    data += section(bits, endian, flags=flags, offset=size + len(sec), size=len(compressed))
                    data += compressed
                    add(f"compressed-{stem}-{kind:x}-{flags:x}", data, "compressed-section-zero")

    # Ghidra's BE declaration heuristic depends on type and the first version byte.
    for type_value in (0, 1, 2, 0x100, 0x102):
        for version in (0, 1, 2, 0x100, 0x1000001):
            data = bytearray(header(type=type_value, version=version)); data[5] = 2
            add(f"endian-heuristic-{type_value:x}-{version:x}", data, "endian-heuristic")

    # Fixed-size mutation corpus, deterministic seed; no table allocations involved.
    rng = random.Random(0x474849445241)
    for i in range(96):
        bits = 32 if i & 1 else 64
        endian = "<" if i & 2 else ">"
        data = bytearray(header(bits, endian))
        for _ in range(1 + i % 8):
            data[rng.randrange(4, len(data))] = rng.randrange(256)
        add(f"mutate-{i:03}", data, "deterministic-mutation")

    # Positive signed-long offset plus entry length can overflow Java's range check.
    # These inputs are tiny; only encoded offsets are large. Safe Rust may reject them.
    for offset in (0x7ffffffffffffffc, 0x7fffffffffffffff):
        add(f"java-region-overflow-{offset:x}", header(shoff=offset, shnum=0, shentsize=64),
            "java-region-overflow")

    assert len({row["file"] for row in manifest}) == len(manifest), "Duplicate fixture names"
    (REVIEW / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def classpath():
    jars = sorted(GHIDRA.glob("Ghidra/**/build/libs/*.jar"))
    jars += [Path(s.strip()) for s in (GHIDRA / "build/libraryDependencies.txt").read_text().splitlines()
             if s.strip().endswith(".jar") and Path(s.strip()).is_file()]
    return os.pathsep.join(map(str, dict.fromkeys(jars)))


def execute_java(files, prefix="java"):
    classes = ROOT / "oracle/classes"
    if not (classes / "ElfHeaderOracle.class").exists():
        raise SystemExit("Compile the existing oracle first with python3 oracle/run.py")
    result = subprocess.run([str(JAVA / "java"), "-cp", str(classes) + os.pathsep + classpath(),
                             "ElfHeaderOracle", *map(str, files)],
                            text=True, capture_output=True, check=True, timeout=60)
    (REVIEW / f"{prefix}-stderr.txt").write_text(result.stderr)
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError:
        (REVIEW / f"{prefix}-stdout.txt").write_text(result.stdout)
        raise
    (REVIEW / f"{prefix}-expanded.json").write_text(json.dumps(rows, indent=2) + "\n")
    return rows


def compare(java, rust, manifest):
    expected = {r["file"]: r for r in java}
    observed = {Path(r["file"]).name: r for r in rust}
    mismatches = []
    warnings = []
    categories = {r["file"]: r["category"] for r in manifest}
    if len(observed) != len(rust) or len(expected) != len(java):
        raise AssertionError("Duplicate file identifiers in output")
    for name, want in expected.items():
        have = observed.get(name, {})
        keys = KEYS if want["accepted"] else ("accepted",)
        delta = {key: {"java": want.get(key), "rust": have.get(key)}
                 for key in keys if want.get(key) != have.get(key)}
        if delta:
            mismatches.append(dict(file=name, category=categories[name], fields=delta))
        if want.get("warnings") != have.get("warnings"):
            warnings.append(dict(file=name, java=want.get("warnings"), rust=have.get("warnings")))
    extras = sorted(set(observed) - set(expected))
    report = dict(cases=len(expected), matches=len(expected) - len(mismatches),
                  mismatches=mismatches, warnings=warnings, extra_files=extras)
    (REVIEW / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", type=Path, help="Built ghidra-elf binary")
    parser.add_argument("--reuse-java", action="store_true", help="Reuse recorded oracle results after checking fixture hashes")
    args = parser.parse_args()
    manifest = generate()
    files = [CASES / row["file"] for row in manifest]
    if args.reuse_java:
        snapshot = json.loads((REVIEW / "java-manifest.json").read_text())
        assert snapshot == manifest, "Oracle fixture contents changed; rerun without --reuse-java"
        java = json.loads((REVIEW / "java-expanded.json").read_text())
        assert [r["file"] for r in java] == [p.name for p in files], "Oracle fixture set changed"
    else:
        java = execute_java(files)
        (REVIEW / "java-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Java oracle: {len(java)} bounded cases, {sum(r['accepted'] for r in java)} accepted")
    if args.rust:
        result = subprocess.run([str(args.rust.resolve()), "--compatible", *map(str, files)],
                                capture_output=True, text=True, timeout=60)
        (REVIEW / "rust-stderr.txt").write_text(result.stderr)
        if result.returncode not in (0, 1):
            raise RuntimeError(f"Rust CLI exited {result.returncode}: {result.stderr}")
        rust = json.loads(result.stdout)
        (REVIEW / "rust-expanded.json").write_text(json.dumps(rust, indent=2) + "\n")
        report = compare(java, rust, manifest)
        print(f"Compatible values: {report['matches']}/{report['cases']}; warning differences: {len(report['warnings'])}")
        for mismatch in report["mismatches"][:12]:
            print(json.dumps(mismatch))
        if report["mismatches"] or report["extra_files"] or report["warnings"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
