#!/usr/bin/env python3
"""Build and compare a fresh, bounded original-Java/Rust relocation-table run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from localenv import GHIDRA, cargo_env, resolve, tool  # noqa: E402
COMMIT = '8f2596c425d6ddfb1824d2a0e23771c5c1e9d749'
COMMON = ('phnum', 'shnum', 'symbol_table_count', 'relocation_tables')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New output directory; existing paths refused')
    args = parser.parse_args()
    output = (args.output or ROOT / 'results' / time.strftime('check-%Y%m%d-%H%M%S', time.gmtime())).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'complete': False, 'commands': [], 'scope': 'ElfHeader.parse() up to the relocation tables: DT_REL/RELA/JMPREL/RELR tables and relocation sections'}
    env = cargo_env(dict(os.environ))
    env.update(CARGO_TARGET_DIR=str(ROOT / 'target'), RUSTFLAGS='')
    for key in ('CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
        env.pop(key, None)

    def run(label, command, allowed=(0,), timeout=120):
        record = {'label': label, 'command': list(map(str, command)), 'timeout_seconds': timeout}
        report['commands'].append(record)
        start = time.monotonic()
        try:
            result = subprocess.run(command, env=env, capture_output=True, timeout=timeout)
            record.update(exit_code=result.returncode, timed_out=False)
            (output / (label + '.stdout')).write_bytes(result.stdout)
            (output / (label + '.stderr')).write_bytes(result.stderr)
        except subprocess.TimeoutExpired as error:
            record.update(exit_code=None, timed_out=True)
            (output / (label + '.stdout')).write_bytes(error.stdout or b'')
            (output / (label + '.stderr')).write_bytes(error.stderr or b'')
            raise
        finally:
            record['elapsed_seconds'] = time.monotonic() - start
        if result.returncode not in allowed:
            raise RuntimeError(f'{label} exited {result.returncode}; see retained stdout/stderr')
        return result

    try:
        commit = run('ghidra-commit', ['git', '-C', GHIDRA, 'rev-parse', 'HEAD']).stdout.decode().strip()
        if commit != COMMIT:
            # The pinned source hashes below are the real gate; a later checkout
            # with unchanged reference sources is accepted.
            report['ghidra_commit_differs_from_reference'] = COMMIT
        report['ghidra_commit'] = commit
        pins = json.loads((ROOT / 'reference.json').read_text())['pinned_reference_sha256']
        if any(sha(resolve(path)) != expected for path, expected in pins.items()):
            raise RuntimeError('Pinned original Java or parent Rust source changed')
        report['pinned_reference_verified'] = True
        sources = [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', *sorted((ROOT / 'src').glob('*.rs')),
                   Path(__file__).resolve(), ROOT / 'reference.json', *sorted((ROOT / 'oracle').glob('*.py')),
                   *sorted((ROOT / 'oracle').glob('*.java')), ROOT.parent / 'Cargo.toml',
                   ROOT.parent / 'src/lib.rs', ROOT.parent / 'section-headers/Cargo.toml',
                   ROOT.parent / 'section-headers/src/lib.rs', ROOT.parent / 'program-headers/Cargo.toml',
                   ROOT.parent / 'program-headers/src/lib.rs', ROOT.parent / 'symbol-tables/Cargo.toml',
                   ROOT.parent / 'symbol-tables/src/lib.rs', ROOT.parent / 'dynamic-table/Cargo.toml',
                   ROOT.parent / 'dynamic-table/src/lib.rs', ROOT.parent / 'dynamic-table/oracle/fixtures.py']
        sources += [GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin' / suffix
                    for suffix in ('format/elf/ElfHeader.java', 'format/elf/ElfSectionHeader.java',
                                   'format/elf/ElfProgramHeader.java', 'format/elf/ElfDynamicTable.java',
                                   'format/elf/ElfDynamic.java',
                                   'format/elf/ElfCompressedSectionHeader.java',
                                   'format/elf/ElfStringTable.java', 'format/elf/ElfSymbolTable.java',
                                   'format/elf/ElfSymbol.java', 'format/elf/ElfRelocationTable.java',
                                   'format/elf/ElfRelocation.java',
                                   'UnlimitedByteProviderWrapper.java', 'ByteProviderWrapper.java',
                                   'BinaryReader.java')]
        hashes = {str(path): sha(path) for path in sources}
        report['source_sha256'] = hashes
        for index, path in enumerate(sources):
            destination = output / 'sources' / f'{index:02d}-{path.name}'
            destination.parent.mkdir(exist_ok=True)
            shutil.copyfile(path, destination)
        cargo = tool('cargo', env)
        base = [cargo, 'test', '--manifest-path', ROOT / 'Cargo.toml', '--offline', '--locked', '--lib']
        run('unit-debug', base)
        run('unit-release', [*base, '--release'])
        run('build-release', [cargo, 'build', '--manifest-path', ROOT / 'Cargo.toml',
                              '--offline', '--locked', '--release', '--bin', 'ghidra-elf-relocations'])
        binary = ROOT / 'target/release/ghidra-elf-relocations'
        artifact = output / 'ghidra-elf-relocations'
        shutil.copyfile(binary, artifact)
        report['rust_binary_sha256'] = sha(artifact)
        java = output / 'java'
        run('java-oracle', [sys.executable, ROOT / 'oracle/run.py', '--output', java])
        manifest = json.loads((java / 'manifest.json').read_text())
        cases = manifest['cases']
        fixtures = [java / 'fixtures' / case['file'] for case in cases]
        for case, path in zip(cases, fixtures, strict=True):
            if sha(path) != case['sha256'] or path.stat().st_size != case['length']:
                raise RuntimeError(f'Fixture manifest mismatch: {path}')
        rust = run('rust-compatible', [binary, '--compatible', *fixtures], allowed=(0, 1), timeout=300)
        observed = json.loads(rust.stdout)
        reference = json.loads((java / 'baseline.json').read_text())
        if len(observed) != len(cases) or len(reference) != len(cases):
            raise RuntimeError('Oracle/Rust result count differs from the frozen manifest')
        by_name = {row['file']: row for row in reference}
        rust_names = [row['file'] for row in observed]
        if len(by_name) != len(cases) or rust_names != [case['file'] for case in cases]:
            raise RuntimeError('Duplicate or reordered case names')
        expected_exit = int(any(not row['accepted'] for row in observed))
        if rust.returncode != expected_exit:
            raise RuntimeError('Rust process exit does not match per-input acceptance')
        matches, exceptions, mismatches = [], [], []
        for case, actual in zip(cases, observed, strict=True):
            expected = by_name[case['file']]
            difference = case.get('expected_difference')
            if difference:
                ok = (expected['accepted'] == difference['java_accepted']
                      and actual['accepted'] is False
                      and actual.get('error_type') == difference['rust_error'])
                result = {'file': case['file'], 'expected': difference, 'passed': ok,
                          'java': expected, 'rust': actual}
                exceptions.append(result)
                if not ok:
                    mismatches.append(result)
                continue
            keys = ['accepted', 'warnings', *(COMMON if expected['accepted'] else ())]
            differences = {key: {'java': expected.get(key), 'rust': actual.get(key)}
                           for key in keys if expected.get(key) != actual.get(key)}
            if differences:
                mismatches.append({'file': case['file'], 'differences': differences})
            else:
                matches.append(case['file'])
        # Strict mode may reject more than Java, but anything it accepts must
        # carry exactly Java's values, and canonical tables must be accepted.
        strict = run('rust-strict', [binary, '--strict', *fixtures], allowed=(0, 1), timeout=120)
        strict_rows = json.loads(strict.stdout)
        if [row['file'] for row in strict_rows] != rust_names:
            raise RuntimeError('Strict result inventory differs from the frozen manifest')
        strict_accepted = []
        for case, actual in zip(cases, strict_rows, strict=True):
            expected = by_name[case['file']]
            if case['group'] == 'canonical' and not actual['accepted']:
                mismatches.append({'file': case['file'], 'strict_rejected_canonical': actual.get('error_type')})
            if not actual['accepted']:
                continue
            strict_accepted.append(case['file'])
            if not expected['accepted']:
                mismatches.append({'file': case['file'], 'strict_accepted_java_rejected': True})
                continue
            differences = {key: {'java': expected.get(key), 'strict': actual.get(key)}
                           for key in ('warnings', *COMMON) if expected.get(key) != actual.get(key)}
            if differences:
                mismatches.append({'file': case['file'], 'strict_differences': differences})
        report.update(parity_case_count=len(matches), safety_exception_count=len(exceptions),
                      parity_cases=matches, safety_exceptions=exceptions, mismatches=mismatches,
                      strict_accepted_count=len(strict_accepted), fixture_count=len(cases))
        report['source_unchanged'] = all(sha(Path(path)) == expected for path, expected in hashes.items())
        report['binary_unchanged'] = sha(binary) == report['rust_binary_sha256']
        report['complete'] = not mismatches and report['source_unchanged'] and report['binary_unchanged']
        if not report['complete']:
            raise RuntimeError('Differential gate failed; see summary.json')
        print(f'PASS: {len(matches)} original Java parity cases; {len(exceptions)} separate safety exceptions; '
              f'{len(strict_accepted)} strict acceptances identical to Java')
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        save(output / 'summary.json', report)
        print(output / 'summary.json', flush=True)


if __name__ == '__main__':
    main()
