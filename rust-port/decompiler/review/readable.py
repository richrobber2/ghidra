#!/usr/bin/env python3
"""Readable-Rust gate: readable Rust against guarded C and the original code.

For each shared library, `rust-ghidra analyze --lang both` writes guarded C and
Rust; the Rust is readable wherever the readable emitter accepts a function.
For every function written as readable Rust, the runner calls three versions
on the same vectors: the readable Rust, the guarded C, and the function itself
inside the original library, loaded with ctypes. The readable emitter accepts
only code whose memory is its own stack frame and whose calls are local or
abort, so calling the original with arbitrary integer arguments is safe.

The three must agree on every vector: the same result, or an abort in all
three. Each vector runs in its own forked child. Results, commands and the
reasons functions stay guarded are kept in the fresh output directory.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys

from rust_backend import DEFAULT_INPUTS, vectors

FUNCTION = ctypes.CFUNCTYPE(ctypes.c_uint64, *[ctypes.c_uint64] * 6)


def load_base(library: str, first_vaddr: int) -> int:
    """The load bias of `library` in this process, from /proc/self/maps."""
    real = os.path.realpath(library)
    for line in Path('/proc/self/maps').read_text().splitlines():
        fields = line.split()
        if len(fields) >= 6 and os.path.realpath(fields[5]) == real and int(fields[2], 16) == 0:
            return int(fields[0].split('-')[0], 16) - (first_vaddr & ~0xfff)
    raise RuntimeError(f'{library} is not mapped')


def worker() -> int:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    payload = json.load(sys.stdin)
    library = ctypes.CDLL(payload['library'])
    if 'address' in payload:
        function = FUNCTION(load_base(payload['library'], payload['first_vaddr']) + payload['address'])
    else:
        function = getattr(library, payload['function'])
        function.argtypes = [ctypes.c_uint64] * 6
        function.restype = ctypes.c_uint64
    for case in payload['inputs']:
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read)
            resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
            os.write(write, str(int(function(*case))).encode())
            os._exit(0)
        os.close(write)
        value = b''
        while chunk := os.read(read, 64):
            value += chunk
        os.close(read)
        _, status = os.waitpid(pid, 0)
        if os.WIFSIGNALED(status):
            number = os.WTERMSIG(status)
            print('abort' if number == signal.SIGABRT else f'signal {number}', flush=True)
        else:
            print(value.decode() if os.WEXITSTATUS(status) == 0 else f'exit {os.WEXITSTATUS(status)}', flush=True)
    return 0


def behaviour(payload: dict, count: int) -> list[str]:
    child = subprocess.run([sys.executable, __file__, '--worker'], input=json.dumps(payload).encode(),
                           capture_output=True, timeout=600)
    results = child.stdout.decode().splitlines()
    if child.returncode != 0 or len(results) != count:
        results.append(f'worker exit {child.returncode}: {child.stderr.decode()[-300:]}')
    return results


def first_load(path: Path) -> int:
    for line in subprocess.run(['readelf', '-W', '-l', str(path)], capture_output=True, text=True).stdout.splitlines():
        fields = line.split()
        if fields[:1] == ['LOAD']:
            return int(fields[2], 16)
    raise RuntimeError(f'{path} has no PT_LOAD')


def main() -> int:
    if '--worker' in sys.argv[1:]:
        return worker()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new result directory')
    parser.add_argument('--cli', type=Path, required=True, help='rust-ghidra executable')
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--rustc', default='rustc')
    parser.add_argument('--max-functions', type=int, default=1000)
    parser.add_argument('--random', type=int, default=48, help='random vectors per kind')
    parser.add_argument('inputs', nargs='*', default=DEFAULT_INPUTS)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    inputs = vectors(args.random)
    (output / 'inputs.json').write_text(json.dumps(inputs) + '\n')
    report = {'files': [], 'decompiled': 0, 'readable': 0, 'matched': 0, 'aborting_vectors': 0,
              'guarded_reasons': Counter(), 'mismatches': [], 'errors': []}
    for index, path in enumerate(map(Path, args.inputs)):
        if not path.is_file():
            continue
        directory = output / f'{index:02d}-{path.name}'
        subprocess.run([str(args.cli), 'analyze', str(path), '--lang', 'both', '--max-functions',
                        str(args.max_functions), '--output', str(directory)], capture_output=True)
        manifest = json.loads((directory / 'manifest.json').read_text())
        rows = [row for row in manifest.get('functions', []) if row['status'] == 'ok']
        readable = [row for row in rows if row.get('rust_style') == 'readable']
        report['decompiled'] += len(rows)
        report['readable'] += len(readable)
        report['guarded_reasons'].update(row['readable_error'] for row in rows if 'readable_error' in row)
        report['files'].append({'input': str(path), 'decompiled': len(rows), 'readable': len(readable)})
        if not readable:
            continue
        c_library, rust_library = directory / 'c.so', directory / 'rust.so'
        builds = [[args.cc, '-std=c11', '-O2', '-fPIC', '-shared', '-nostdlib', '-fno-stack-protector',
                   '-Werror=implicit-function-declaration', '-Werror=return-type',
                   str(directory / 'decompiled.c'), '-o', str(c_library)],
                  [args.rustc, '--edition', '2024', '-O', '--crate-type', 'cdylib', '-C', 'panic=abort',
                   '-D', 'warnings', str(directory / 'decompiled.rs'), '-o', str(rust_library)]]
        failed = False
        for command in builds:
            build = subprocess.run(command, capture_output=True)
            if build.returncode != 0:
                failed = True
                report['errors'].append({'input': str(path), 'command': command,
                                         'stderr': build.stderr.decode()[-4000:]})
        if failed:
            continue
        vaddr = first_load(path)
        for row in readable:
            name = row['generated_function']
            results = {
                'rust': behaviour({'library': str(rust_library), 'function': name, 'inputs': inputs}, len(inputs)),
                'c': behaviour({'library': str(c_library), 'function': name, 'inputs': inputs}, len(inputs)),
                'native': behaviour({'library': str(path), 'address': int(row['function']['address_hex'], 16),
                                     'first_vaddr': vaddr, 'inputs': inputs}, len(inputs)),
            }
            report['aborting_vectors'] += results['native'].count('abort')
            if results['rust'] == results['c'] == results['native']:
                report['matched'] += 1
                continue
            first = next(i for i in range(len(inputs) + 1)
                         if len({tuple(r[i:i + 1]) for r in results.values()}) > 1)
            report['mismatches'].append({'input': str(path), 'function': row['function']['name'],
                                         'generated': name, 'vector': inputs[first] if first < len(inputs) else None,
                                         **{k: v[first:first + 1] for k, v in results.items()}})
    report['vectors_per_function'] = len(inputs)
    report['guarded_reasons'] = dict(report['guarded_reasons'].most_common())
    passed = report['readable'] > 0 and not report['mismatches'] and not report['errors']
    report['status'] = 'passed' if passed else 'failed'
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['status'].upper()}: {report['matched']}/{report['readable']} readable functions agree with "
          f"guarded C and the original code over {len(inputs)} vectors ({report['decompiled']} decompiled, "
          f"{report['aborting_vectors']} aborts matched); {len(report['mismatches'])} mismatches, "
          f"{len(report['errors'])} build errors; {output / 'summary.json'}")
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
