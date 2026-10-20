#!/usr/bin/env python3
"""Build, test and compare the Rust x86-64 relocation handler with Ghidra's Java one.

Runs the unit tests, then applies every relocation of the synthetic fixtures in
oracle/fixtures.py and of a corpus of real system ELF files with both the Rust
CLI and the original X86_64_ElfRelocationHandler (oracle/), and requires every
reported line to match: per-relocation status and byte length, every memory
write, the import log, loader messages, bookmarks, console and stdout output,
artificial relocation entries and the %got allocation.
"""
import argparse
from collections import Counter
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
sys.path.insert(0, str(ROOT / 'oracle'))
from localenv import GHIDRA, cargo_env, resolve, tool  # noqa: E402
import fixtures  # noqa: E402
import run as oracle  # noqa: E402

LISTS = ('relocations', 'writes', 'log', 'loader_log', 'bookmarks', 'console', 'stdout', 'artificial',
         'created_symbols', 'got_entries')
SCALARS = ('accepted', 'relocation_count', 'status_counts', 'type_counts', 'got_allocation', 'aborted')
MAX_BYTES = 64 * 1024 * 1024
DEFAULT_CORPUS = ('/usr/lib/x86_64-linux-gnu', '/usr/bin')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def corpus_files(directories):
    found = []
    for directory in directories:
        directory = Path(directory)
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if directory.name == 'x86_64-linux-gnu' and '.so' not in path.name:
                continue
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
                    continue
                with path.open('rb') as handle:
                    head = handle.read(18)
            except OSError:
                continue
            if head[:4] == b'\x7fELF' and len(head) == 18:
                found.append((path, int.from_bytes(head[16:18], 'little')))
    return found


def compare(java, rust):
    """Differences between two result rows."""
    if java.get('accepted') is False or rust.get('accepted') is False:
        keys = ('accepted', 'error')
    else:
        keys = SCALARS + LISTS
    return {key: {'java': java.get(key), 'rust': rust.get(key)} for key in keys if java.get(key) != rust.get(key)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New output directory; existing paths refused')
    parser.add_argument('--corpus', nargs='*', default=list(DEFAULT_CORPUS),
                        help='Directories of real ELF files (default: %(default)s); none to skip')
    args = parser.parse_args()
    output = (args.output or ROOT / 'results' / time.strftime('check-%Y%m%d-%H%M%S', time.gmtime())).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'complete': False, 'commands': [],
              'scope': 'X86_64_ElfRelocationHandler with its ElfGotRelocationContext, over every relocation '
                       'of each input, under the memory and symbol model in src/model.rs'}
    env = cargo_env(dict(os.environ))
    env.update(CARGO_TARGET_DIR=str(ROOT / 'target'), RUSTFLAGS='')
    for key in ('CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
        env.pop(key, None)

    def run(label, command, allowed=(0,), timeout=600):
        record = {'label': label, 'command': list(map(str, command)), 'timeout_seconds': timeout}
        report['commands'].append(record)
        start = time.monotonic()
        try:
            result = subprocess.run(list(map(str, command)), env=env, capture_output=True, timeout=timeout)
            record['exit_code'] = result.returncode
            (output / (label + '.stdout')).write_bytes(result.stdout)
            (output / (label + '.stderr')).write_bytes(result.stderr)
        finally:
            record['elapsed_seconds'] = time.monotonic() - start
        if result.returncode not in allowed:
            raise RuntimeError(f'{label} exited {result.returncode}; see {output / (label + ".stderr")}')
        return result

    try:
        report['ghidra_commit'] = run('ghidra-commit', ['git', 'rev-parse', 'HEAD']).stdout.decode().strip()
        reference = json.loads((ROOT / 'reference.json').read_text())
        changed = [path for path, expected in reference['pinned_reference_sha256'].items()
                   if sha(resolve(path)) != expected]
        if changed:
            raise RuntimeError(f'Pinned original Java or parent Rust source changed: {changed}')
        report['pinned_reference_verified'] = True

        cargo = tool('cargo', env)
        manifest_arg = ['--manifest-path', ROOT / 'Cargo.toml']
        run('fmt-check', [cargo, 'fmt', *manifest_arg, '--check'])
        run('unit-debug', [cargo, 'test', *manifest_arg, '--offline', '--locked'])
        run('unit-release', [cargo, 'test', *manifest_arg, '--offline', '--locked', '--release'])
        run('build-release', [cargo, 'build', *manifest_arg, '--offline', '--locked', '--release',
                              '--bin', 'ghidra-elf-x86-64-relocations'])
        binary = output / 'ghidra-elf-x86-64-relocations'
        shutil.copyfile(ROOT / 'target/release/ghidra-elf-x86-64-relocations', binary)
        binary.chmod(0o755)
        report['rust_binary_sha256'] = sha(binary)

        classes = output / 'classes'
        cp, jars, build = oracle.compile_oracle(classes)
        report['ghidra_build'] = str(build)
        report['classpath_jars'] = len(jars)
        # When the jars come from another checkout, its copies of the pinned
        # Java sources must match the ones verified above.
        if build != GHIDRA:
            for path, expected in reference['pinned_reference_sha256'].items():
                local = resolve(path)
                try:
                    relative = local.relative_to(GHIDRA)
                except ValueError:
                    continue
                if relative.parts[0] == 'rust-port':
                    continue
                if sha(build / relative) != expected:
                    raise RuntimeError(f'{build / relative} differs from the pinned source')

        def differential(label, rows, digest):
            manifest = output / f'{label}-manifest.txt'
            manifest.write_text(''.join(f'{path}\t{adjust}\t{int(unresolved)}\n' for path, adjust, unresolved in rows))
            java_out = output / f'{label}-java.json'
            start = time.monotonic()
            result = oracle.run_oracle(cp, classes, manifest, java_out, digest=digest, timeout=3600)
            (output / f'{label}-java.stderr').write_bytes(result.stderr)
            report['commands'].append({'label': f'{label}-java', 'exit_code': result.returncode,
                                       'elapsed_seconds': time.monotonic() - start})
            if result.returncode != 0:
                raise RuntimeError(f'{label} Java oracle exited {result.returncode}; see {label}-java.stderr')
            command = [binary, *(['--digest'] if digest else []), '--manifest', manifest]
            rust = run(f'{label}-rust', command, allowed=(0, 1), timeout=3600)
            (output / f'{label}-rust.json').write_bytes(rust.stdout)
            java_rows = json.loads(java_out.read_text())
            rust_rows = json.loads(rust.stdout)
            if len(java_rows) != len(rows) or len(rust_rows) != len(rows):
                raise RuntimeError(f'{label}: result counts differ from the manifest')
            mismatches = []
            for (path, _, _), java, rust_row in zip(rows, java_rows, rust_rows, strict=True):
                if java['file'] != Path(path).name or rust_row['file'] != Path(path).name:
                    raise RuntimeError(f'{label}: result order differs from the manifest')
                difference = compare(java, rust_row)
                if difference:
                    mismatches.append({'file': str(path), 'differences': difference})
            return java_rows, mismatches

        def summarize(rows, digest):
            accepted = [row for row in rows if row['accepted']]
            statuses, types = Counter(), Counter()
            for row in accepted:
                statuses.update(row['status_counts'])
                types.update(row['type_counts'])
            count = (lambda row, key: row[key]['count']) if digest else (lambda row, key: len(row[key]))
            return {
                'inputs': len(rows),
                'accepted': len(accepted),
                'rejected': dict(Counter(row['error'] for row in rows if not row['accepted'])),
                'relocations': sum(row['relocation_count'] for row in accepted),
                'status_counts': dict(statuses),
                'type_counts': {key: types[key] for key in sorted(types, key=int)},
                'writes': sum(count(row, 'writes') for row in accepted),
                'log_lines': sum(count(row, 'log') for row in accepted),
                'console_lines': sum(count(row, 'console') for row in accepted),
                'artificial_entries': sum(count(row, 'artificial') for row in accepted),
                'got_allocated': sum(row['got_allocation'] not in ('not-attempted', 'failed') for row in accepted),
                'aborted_runs': sum(row['aborted'] is not None for row in accepted),
            }

        # Synthetic fixtures.
        generated = fixtures.generate(output / 'fixtures')
        (output / 'fixtures-manifest.json').write_text(json.dumps(generated, indent=2) + '\n')
        cases = generated['cases']
        rows = [(output / 'fixtures' / case['file'], case['adjust'], case['unresolved']) for case in cases]
        java_rows, mismatches = differential('fixtures', rows, digest=False)
        synthetic = summarize(java_rows, digest=False)
        groups = Counter(case['group'] for case in cases)
        synthetic['groups'] = dict(groups)
        # Every type id the handler knows (and some it does not) reaches it.
        types_seen = Counter()
        for row in java_rows:
            if row['accepted']:
                for line in row['relocations']:
                    types_seen[int(line.split()[3])] += 1
        expected_types = set(fixtures.TYPES + fixtures.EXTRA_TYPES) - {0}
        missing = sorted(expected_types - set(types_seen))
        if missing:
            mismatches.append({'missing_type_coverage': missing})
        synthetic['type_ids_covered'] = len(expected_types & set(types_seen))
        if synthetic['aborted_runs'] < 2 or synthetic['got_allocated'] == 0 or synthetic['artificial_entries'] == 0:
            mismatches.append({'coverage': 'expected aborted runs, %got allocations and relaxations'})
        report['synthetic'] = synthetic
        report['synthetic_mismatches'] = mismatches

        # Real files: ET_EXEC at its own base, others at Ghidra's default 0x100000,
        # then again with every undefined symbol left unresolved.
        corpus = corpus_files(args.corpus)
        rows = [(path, '0' if elf_type == 2 else '100000', False) for path, elf_type in corpus]
        corpus_mismatches = []
        report['corpus'] = {'inputs': 0}
        if rows:
            java_rows, corpus_mismatches = differential('corpus', rows, digest=True)
            report['corpus'] = summarize(java_rows, digest=True)
            unresolved = [(path, adjust, True) for path, adjust, _ in rows]
            java_rows, more = differential('corpus-unresolved', unresolved, digest=True)
            corpus_mismatches += more
            report['corpus_unresolved'] = summarize(java_rows, digest=True)
        report['corpus_directories'] = args.corpus
        report['corpus_mismatches'] = corpus_mismatches[:50]
        report['corpus_mismatch_count'] = len(corpus_mismatches)

        report['binary_unchanged'] = sha(ROOT / 'target/release/ghidra-elf-x86-64-relocations') == report['rust_binary_sha256']
        report['complete'] = not mismatches and not corpus_mismatches and report['binary_unchanged']
        if not report['complete']:
            raise RuntimeError('Differential gate failed; see summary.json')
        s, c = report['synthetic'], report['corpus']
        print(f"PASS: {s['inputs']} synthetic inputs ({s['accepted']} run, {s['relocations']} relocations, "
              f"{s['type_ids_covered']} type ids) and {c['inputs']} corpus files ({c.get('accepted', 0)} run, "
              f"{c.get('relocations', 0)} relocations) identical to Java")
        print('synthetic statuses:', s['status_counts'])
        print('corpus statuses:', c.get('status_counts'), 'rejected:', c.get('rejected'))
        if 'corpus_unresolved' in report:
            print('corpus statuses, externals unresolved:', report['corpus_unresolved']['status_counts'])
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
        print(output / 'summary.json', flush=True)


if __name__ == '__main__':
    main()
