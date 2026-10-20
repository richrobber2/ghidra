#!/usr/bin/env python3
"""Compare original Java and Rust string/symbol tables over real ELF files.

Scans the given directories (default /usr/bin and /usr/lib/x86_64-linux-gnu)
for regular ELF files, adds a freshly compiled object whose debug sections are
zlib-compressed when gcc and objcopy are available, then runs the unchanged
Java parser and the Rust compatibility CLI on the same inputs. Every compared
field must match exactly.
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

COMMON = ('accepted', 'warnings', 'shnum', 'string_tables', 'symbol_tables')
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


def compressed_object(output):
    gcc, objcopy = shutil.which('gcc'), shutil.which('objcopy')
    if not gcc or not objcopy:
        return []
    source = output / 'compressed.c'
    source.write_text('int square(int x) { return x * x; }\nint main(void) { return square(3); }\n')
    built = []
    for flag in ('-m64', '-m32'):
        plain = output / f'debug{flag}.o'
        if subprocess.run([gcc, flag, '-g', '-c', source, '-o', plain], capture_output=True).returncode:
            continue
        packed = output / f'compressed-debug{flag}.o'
        if subprocess.run([objcopy, '--compress-debug-sections=zlib', plain, packed],
                          capture_output=True).returncode == 0:
            built += [plain, packed]
    # Between 0xff00 and the 65536-section bound: forces SHN_XINDEX symbols and
    # an SHT_SYMTAB_SHNDX table.
    many = output / 'many-sections.c'
    many.write_text(''.join(f'int f{i}(void) {{ return {i}; }}\n' for i in range(65400)))
    packed = output / 'many-sections.o'
    if subprocess.run([gcc, '-c', '-ffunction-sections', '-fdata-sections', many, '-o', packed],
                      capture_output=True).returncode == 0:
        built.append(packed)
    return built


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New output directory')
    parser.add_argument('--limit', type=int, default=3000)
    parser.add_argument('directories', nargs='*', default=['/usr/bin', '/usr/lib/x86_64-linux-gnu'])
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = cargo_env(dict(os.environ))
    env.update(CARGO_TARGET_DIR=str(ROOT / 'target'))
    subprocess.run([tool('cargo', env), 'build', '--manifest-path', ROOT / 'Cargo.toml', '--offline',
                    '--locked', '--release', '--bin', 'ghidra-elf-symbols'], env=env, check=True)
    files = compressed_object(output) + elf_files(args.directories, args.limit)
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
    subprocess.run([JAVA / 'javac', '-cp', cp, '-d', classes, ROOT / 'oracle/ElfSymbolsOracle.java'],
                   check=True)
    java = subprocess.run([JAVA / 'java', '-Xmx4g', '-cp', str(classes) + os.pathsep + cp,
                           'ElfSymbolsOracle', *files], capture_output=True, check=True)
    rust = subprocess.run([ROOT / 'target/release/ghidra-elf-symbols', '--compatible', *files],
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
    tables = [t for row in java_rows for t in row.get('symbol_tables', ())]
    symbols = sum(len(t['symbols']) for t in tables)
    summary = dict(files=len(files), symbol_tables=len(tables), symbols=symbols,
                   java_accepted=sum(row['accepted'] for row in java_rows),
                   mismatches=mismatches, inputs=[str(path) for path in files])
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(f'{"PASS" if not mismatches else "FAIL"}: {len(files)} files, {len(tables)} symbol tables, '
          f'{symbols} symbols, {len(mismatches)} mismatches; {output / "summary.json"}')
    sys.exit(1 if mismatches else 0)


if __name__ == '__main__':
    main()
