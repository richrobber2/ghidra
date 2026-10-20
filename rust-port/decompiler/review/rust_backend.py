#!/usr/bin/env python3
"""Differential gate: generated Rust against generated C on real ELF files.

For each input, `rust-ghidra analyze --lang both` writes decompiled.c and
decompiled.rs from the same lifted IR. The runner compiles both (gcc and
rustc), calls every decompiled function in each library on the same fixed
input vectors, and requires identical behaviour: the same result for each
vector, or a guard abort on the same vector. Each vector runs in its own
forked child, so one abort does not hide later results.
Every command and comparison is kept in the fresh output directory.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import random
import resource
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MASK = (1 << 64) - 1
DEFAULT_INPUTS = ['/usr/lib/x86_64-linux-gnu/libz.so.1', '/usr/lib/x86_64-linux-gnu/libc.so.6',
                  '/usr/lib/x86_64-linux-gnu/libm.so.6', '/usr/lib/x86_64-linux-gnu/libresolv.so.2',
                  '/usr/lib/x86_64-linux-gnu/libnsl.so.1', '/usr/lib/x86_64-linux-gnu/libbz2.so.1.0',
                  '/usr/lib/x86_64-linux-gnu/liblzma.so.5', '/usr/lib/x86_64-linux-gnu/libcrypt.so.1',
                  '/usr/lib/x86_64-linux-gnu/libuuid.so.1', '/usr/lib/x86_64-linux-gnu/libexpat.so.1']


def vectors(count: int) -> list[list[int]]:
    values = [0, 1, 2, 7, 31, 32, 63, 64, 255, (1 << 31) - 1, 1 << 31, (1 << 32) - 1, 1 << 32,
              (1 << 63) - 1, 1 << 63, MASK]
    cases = [[v] * 6 for v in values]
    rng = random.Random(0x5eed)
    cases += [[rng.getrandbits(64) for _ in range(6)] for _ in range(count)]
    cases += [[rng.choice(values) for _ in range(6)] for _ in range(count)]
    return cases


def worker() -> int:
    """Load one library and call one function per vector in a forked child, so
    a guard abort costs one vector rather than the rest of the run."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    payload = json.load(sys.stdin)
    function = getattr(ctypes.CDLL(payload['library']), payload['function'])
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
            signal_number = os.WTERMSIG(status)
            print('abort' if signal_number == signal.SIGABRT else f'signal {signal_number}', flush=True)
        else:
            print(value.decode() if os.WEXITSTATUS(status) == 0 else f'exit {os.WEXITSTATUS(status)}', flush=True)
    return 0


def behaviour(library: Path, function: str, inputs: list[list[int]]) -> list[str]:
    """Each vector's result, or 'abort' where a guard aborted."""
    payload = json.dumps({'library': str(library), 'function': function, 'inputs': inputs})
    child = subprocess.run([sys.executable, __file__, '--worker'], input=payload.encode(),
                           capture_output=True, timeout=600)
    results = child.stdout.decode().splitlines()
    if child.returncode != 0 or len(results) != len(inputs):
        results.append(f'worker exit {child.returncode}')
    return results


def main() -> int:
    if '--worker' in sys.argv[1:]:
        return worker()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new result directory')
    parser.add_argument('--cli', type=Path, required=True, help='rust-ghidra executable')
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--rustc', default='rustc')
    parser.add_argument('--max-functions', type=int, default=100)
    parser.add_argument('--random', type=int, default=48, help='random vectors per kind')
    parser.add_argument('inputs', nargs='*', default=DEFAULT_INPUTS)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    inputs = vectors(args.random)
    (output / 'inputs.json').write_text(json.dumps(inputs) + '\n')
    report = {'files': [], 'functions': 0, 'matched': 0, 'aborting_vectors': 0, 'image_functions': 0,
              'mismatches': [], 'errors': []}
    for index, path in enumerate(map(Path, args.inputs)):
        if not path.is_file():
            continue
        directory = output / f'{index:02d}-{path.name}'
        analyze = subprocess.run([str(args.cli), 'analyze', str(path), '--lang', 'both', '--max-functions',
                                  str(args.max_functions), '--output', str(directory)], capture_output=True)
        manifest = json.loads((directory / 'manifest.json').read_text())
        rows = [row for row in manifest.get('functions', []) if row['status'] == 'ok']
        entry = {'input': str(path), 'analyze_exit': analyze.returncode, 'decompiled': len(rows)}
        report['files'].append(entry)
        if not rows:
            continue
        c_library, rust_library = directory / 'c.so', directory / 'rust.so'
        builds = [[args.cc, '-std=c11', '-O2', '-fPIC', '-shared', '-nostdlib', '-fno-stack-protector',
                   '-Werror=implicit-function-declaration', '-Werror=return-type',
                   str(directory / 'decompiled.c'), '-o', str(c_library)],
                  [args.rustc, '--edition', '2024', '-O', '--crate-type', 'cdylib', '-C', 'panic=abort',
                   '-D', 'warnings', str(directory / 'decompiled.rs'), '-o', str(rust_library)]]
        for command in builds:
            build = subprocess.run(command, capture_output=True)
            if build.returncode != 0:
                report['errors'].append({'input': str(path), 'command': command,
                                         'stderr': build.stderr.decode()[-4000:]})
        if report['errors'] and report['errors'][-1]['input'] == str(path):
            continue
        for row in rows:
            name = row['generated_function']
            c_result = behaviour(c_library, name, inputs)
            rust_result = behaviour(rust_library, name, inputs)
            report['functions'] += 1
            report['image_functions'] += bool(row['image_objects'])
            report['aborting_vectors'] += c_result.count('abort')
            if c_result == rust_result:
                report['matched'] += 1
            else:
                first = next(i for i, (a, b) in enumerate(zip(c_result, rust_result)) if a != b)
                report['mismatches'].append({'input': str(path), 'function': name, 'vector': inputs[first],
                                             'c': c_result[first], 'rust': rust_result[first]})
    report['vectors_per_function'] = len(inputs)
    passed = report['functions'] > 0 and not report['mismatches'] and not report['errors']
    report['status'] = 'passed' if passed else 'failed'
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['status'].upper()}: {report['matched']}/{report['functions']} functions behave identically "
          f"in generated C and Rust over {len(inputs)} vectors ({report['image_functions']} use image memory, "
          f"{report['aborting_vectors']} guard aborts matched); {len(report['errors'])} build errors; "
          f"{output / 'summary.json'}")
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
