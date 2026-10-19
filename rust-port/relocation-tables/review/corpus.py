#!/usr/bin/env python3
"""Compare original Java and Rust relocation tables over real ELF files.

Scans the given directories (default /usr/bin and /usr/lib/x86_64-linux-gnu)
for regular ELF files and adds, when gcc is available, freshly built objects:
shared objects with lazy and immediate binding, with `DT_RELR` packed
relocations where the linker supports them, 32-bit `DT_REL` ones and
relocatable objects with per-section tables. It also writes a copy of the first
--headerless files with the section-header fields cleared, so the tables must be
found through the dynamic table alone. Both sides print each table's fields and
an FNV-1a digest of its relocations (--digest), and every compared field must
match exactly. Strict mode runs too: anything it accepts must carry Java's
values.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from localenv import GHIDRA, JAVA, cargo_env, tool  # noqa: E402

COMMON = ('accepted', 'warnings', 'phnum', 'shnum', 'symbol_table_count', 'relocation_tables')
MAX_BYTES = 64 * 1024 * 1024


def elf_files(directories, limit):
    found = []
    for directory in directories:
        for path in sorted(Path(directory).rglob('*')):
            if len(found) >= limit:
                return found
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
                    continue
                with path.open('rb') as handle:
                    if handle.read(4) == b'\x7fELF':
                        found.append(path)
            except OSError:
                continue
    return found


def linked_objects(output):
    gcc = shutil.which('gcc')
    if not gcc:
        return []
    source = output / 'shared.c'
    source.write_text('#include <stdio.h>\nint counter;\nint *slots[] = {&counter, &counter, &counter, &counter};\n'
                      'int square(int x) { return x * x; }\n'
                      'void hello(void) { puts("hi"); counter++; }\n')
    built = []
    variants = [('lazy', ['-shared']), ('now', ['-shared', '-Wl,-z,now']),
                ('relr', ['-shared', '-Wl,-z,pack-relative-relocs']),
                ('pie-relr', ['-pie', '-Wl,-z,pack-relative-relocs', '-Wl,--unresolved-symbols=ignore-all']),
                ('object', ['-c'])]
    for flag in ('-m64', '-m32'):
        for name, flags in variants:
            path = output / f'built-{name}{flag}.{"o" if name == "object" else "so"}'
            if subprocess.run([gcc, flag, '-fPIC', *flags, source, '-o', path],
                              capture_output=True).returncode == 0:
                built.append(path)
    return built


def headerless(paths, output, count):
    """Copies with e_shoff, e_shnum and e_shstrndx cleared."""
    directory = output / 'headerless'
    directory.mkdir()
    built = []
    for path in paths:
        if len(built) >= count:
            break
        data = bytearray(path.read_bytes())
        if len(data) < 64 or data[4] not in (1, 2) or data[5] not in (1, 2):
            continue
        order = '<' if data[5] == 1 else '>'
        elf_type = int.from_bytes(data[16:18], 'little' if order == '<' else 'big')
        if elf_type not in (2, 3):
            continue
        if data[4] == 2:
            data[40:48] = bytes(8)
            data[60:64] = bytes(4)
        else:
            data[32:36] = bytes(4)
            data[48:52] = bytes(4)
        copy = directory / ('headerless-' + path.name)
        copy.write_bytes(bytes(data))
        built.append(copy)
    return built


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New output directory')
    parser.add_argument('--limit', type=int, default=3000)
    parser.add_argument('--headerless', type=int, default=400, help='Section-less copies to add')
    parser.add_argument('directories', nargs='*', default=['/usr/bin', '/usr/lib/x86_64-linux-gnu'])
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = cargo_env(dict(os.environ))
    env.update(CARGO_TARGET_DIR=str(ROOT / 'target'))
    subprocess.run([tool('cargo', env), 'build', '--manifest-path', ROOT / 'Cargo.toml', '--offline',
                    '--locked', '--release', '--bin', 'ghidra-elf-relocations'], env=env, check=True)
    real = elf_files(args.directories, args.limit)
    files = linked_objects(output) + real
    files += headerless(files, output, args.headerless)
    names = [path.name for path in files]
    if len(set(names)) != len(names):
        # Results are keyed by file name; keep the first of any duplicate.
        seen, unique = set(), []
        for path in files:
            if path.name not in seen:
                seen.add(path.name)
                unique.append(path)
        files = unique

    jars = sorted(GHIDRA.glob('Ghidra/**/build/libs/*.jar'))
    jars += [Path(s.strip()) for s in (GHIDRA / 'build/libraryDependencies.txt').read_text().splitlines()
             if s.strip().endswith('.jar') and Path(s.strip()).is_file()]
    cp = os.pathsep.join(map(str, dict.fromkeys(jars)))
    classes = output / 'classes'
    classes.mkdir()
    subprocess.run([JAVA / 'javac', '-cp', cp, '-d', classes, ROOT / 'oracle/ElfRelocationsOracle.java'],
                   check=True)
    java = subprocess.run([JAVA / 'java', '-Xmx4g', '-cp', str(classes) + os.pathsep + cp,
                           'ElfRelocationsOracle', '--digest', *files], capture_output=True, check=True)
    rust = subprocess.run([ROOT / 'target/release/ghidra-elf-relocations', '--compatible', '--digest', *files],
                          capture_output=True)
    if rust.returncode not in (0, 1):
        raise RuntimeError(rust.stderr.decode())
    (output / 'java.json').write_bytes(java.stdout)
    (output / 'rust.json').write_bytes(rust.stdout)
    java_rows, rust_rows = json.loads(java.stdout), json.loads(rust.stdout)
    if [r['file'] for r in java_rows] != [r['file'] for r in rust_rows]:
        raise RuntimeError('Java/Rust result inventories differ')
    mismatches = []
    for expected, actual in zip(java_rows, rust_rows, strict=True):
        keys = COMMON if expected['accepted'] else ('accepted', 'warnings')
        differences = {key: {'java': expected.get(key), 'rust': actual.get(key)}
                       for key in keys if expected.get(key) != actual.get(key)}
        if differences:
            mismatches.append({'file': expected['file'], 'differences': differences})
    strict = subprocess.run([ROOT / 'target/release/ghidra-elf-relocations', '--strict', '--digest', *files],
                            capture_output=True)
    (output / 'strict.json').write_bytes(strict.stdout)
    strict_accepted = 0
    for expected, actual in zip(java_rows, json.loads(strict.stdout), strict=True):
        if not actual['accepted']:
            continue
        strict_accepted += 1
        differences = {key: {'java': expected.get(key), 'strict': actual.get(key)}
                       for key in COMMON if expected.get(key) != actual.get(key)}
        if differences:
            mismatches.append({'file': expected['file'], 'strict_differences': differences})
    accepted = [row for row in java_rows if row['accepted']]
    tables = [t for row in accepted for t in row['relocation_tables']]
    found = [t for t in tables if t['section'] is None]
    summary = dict(files=len(files), java_accepted=len(accepted), relocation_tables=len(tables),
                   relocations=sum(t['relocation_count'] for t in tables),
                   relr_tables=sum(t['format'] == 'RELR' for t in tables),
                   relr_relocations=sum(t['relocation_count'] for t in tables if t['format'] == 'RELR'),
                   section_tables=len(tables) - len(found), dynamic_only_tables=len(found),
                   files_with_warnings=sum(bool(row['warnings']) for row in java_rows),
                   strict_accepted=strict_accepted, mismatches=mismatches, inputs=[str(path) for path in files])
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(f'{"PASS" if not mismatches else "FAIL"}: {len(files)} files ({summary["java_accepted"]} accepted), '
          f'{len(tables)} relocation tables with {summary["relocations"]} relocations '
          f'({summary["relr_tables"]} RELR tables, {len(found)} found only through the dynamic table), '
          f'{strict_accepted} strict acceptances, {len(mismatches)} mismatches; {output / "summary.json"}')
    sys.exit(1 if mismatches else 0)


if __name__ == '__main__':
    main()
