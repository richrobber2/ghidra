#!/usr/bin/env python3
"""Freeze the memory-stage workspace and recheck every archived regular file.

Run serially after all writers finish. Toolchains, Cargo caches and the original
Ghidra installation stay external. Historical results, including failures, are
included; the root Cargo target contributes only the runnable CLI.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def files():
    selected = []
    for directory, names, leaves in os.walk(ROOT):
        directory = Path(directory)
        names[:] = sorted(n for n in names if n not in {'__pycache__', '.git'}
                          and not (directory == ROOT and n == 'target'))
        for name in sorted(leaves):
            path = directory / name
            if stat.S_ISREG(path.lstat().st_mode):
                selected.append(path)
    selected.append(ROOT / 'target/release/rust-ghidra')
    previous = json.loads((ROOT.parent / 'artifacts/decompiler-native-first-01.tar.json').read_text())
    for entry in previous['files']:
        relative = entry['path']
        if not relative.startswith('ghidra-rust-port/decompiler/'):
            selected.append(WORKSPACE / relative)
    unique = sorted(set(selected))
    if len(unique) != len(selected):
        raise ValueError('duplicate archive inputs')
    return unique


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='new .tar archive')
    args = parser.parse_args()
    archive = Path(args.output).resolve()
    manifest = Path(str(archive) + '.json')
    if archive.exists() or manifest.exists():
        raise SystemExit('archive and manifest must both be new')
    archive.parent.mkdir(parents=True, exist_ok=True)
    records = []
    with archive.open('xb') as stream, tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as out:
        for path in files():
            before = path.stat()
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f'input is no longer a regular file: {path}')
            data = path.read_bytes()
            after = path.stat()
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError(f'input changed while freezing: {path}')
            name = str(path.relative_to(WORKSPACE))
            info = out.gettarinfo(str(path), arcname=name)
            info.type, info.linkname, info.size = tarfile.REGTYPE, '', len(data)
            out.addfile(info, io.BytesIO(data))
            records.append(dict(path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    expected = {row['path']: row for row in records}
    seen = set()
    with tarfile.open(archive, 'r') as frozen:
        for member in frozen:
            if not member.isfile() or member.name not in expected or member.name in seen:
                raise ValueError(f'unexpected/nonregular/duplicate archive member: {member.name}')
            data = frozen.extractfile(member).read()
            row = expected[member.name]
            if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
                raise ValueError(f'archive contents differ: {member.name}')
            seen.add(member.name)
    if seen != expected.keys():
        raise ValueError('archive omitted declared files')
    result = dict(complete=True, archive=str(archive), sha256=sha(archive),
                  archive_bytes=archive.stat().st_size, file_count=len(records),
                  regular_files_only=True, content_readback_verified=True,
                  external_dependencies=['Rust/Java/C toolchains', 'Cargo registry cache', 'original Ghidra installation'],
                  files=records)
    with manifest.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: result[key] for key in ('complete', 'archive', 'sha256', 'archive_bytes', 'file_count', 'content_readback_verified')}, indent=2))


if __name__ == '__main__':
    main()
