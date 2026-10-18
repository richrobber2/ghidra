#!/usr/bin/env python3
"""Independent bounded program-header edge checks; requires exclusive CPU grant.

Uses original Java oracle source with independent fixture generation and a
struct-based model for strict table extents/record values. No compiler build or
execution occurs on import. Every invocation requires a fresh result directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from localenv import GHIDRA, JAVA  # noqa: E402
U64 = (1 << 64) - 1
I64 = (1 << 63) - 1
COMMON = ('class_bits', 'header_little_endian', 'phnum', 'phentsize',
          'offsets_rewritten', 'entries')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def signed64(value):
    return value if value <= I64 else value - (1 << 64)


def base(bits=64, little=True, count=2, *, stride=None, phoff=128,
         length=None, sizes=None, high=False, extended=None):
    endian = '<' if little else '>'
    record = 56 if bits == 64 else 32
    stride = record if stride is None else stride
    size = max(128 + min(count, 4) * record, 256) if length is None else length
    data = bytearray(size)
    data[:16] = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if little else 2, 1]) + bytes(9)
    header_count = count if extended is None else 65535
    shoff = 64 if extended is not None else 0
    header = (2, 62 if bits == 64 else 3, 1, 0x1234, phoff, shoff, 0,
              64 if bits == 64 else 52, stride, header_count, 64 if bits == 64 else 40, 0, 0)
    struct.pack_into(endian + ('HHIQQQIHHHHHH' if bits == 64 else 'HHIIIIIHHHHHH'), data, 16, *header)
    if extended is not None:
        section_size = 64 if bits == 64 else 40
        data[64:64 + section_size] = bytes(section_size)
        struct.pack_into(endian + 'I', data, 64 + (44 if bits == 64 else 28), extended)
    maximum = U64 if bits == 64 else (1 << 32) - 1
    for index in range(min(count, 4)):
        position = 128 + index * record
        if position + record > len(data):
            break
        file_size = (sizes[index] if sizes is not None else 7 + index)
        # Unknown types/flags and high-bit addresses are legal decoded fields;
        # payload and memory-size relationships are deliberately not validated.
        typ = 0xF1234567 if high else index + 1
        flags = 0x87654321 if high else index + 4
        offset = maximum - index if high else 0x1000 + index * 0x80
        vaddr = maximum - 3 * index if high else 0x8000 + index * 0x40
        paddr = maximum - 5 * index if high else 0x9000 + index * 0x20
        mem_size = maximum - 7 * index if high else file_size & maximum
        align = maximum - 9 * index if high else index
        fields = (typ, flags, offset, vaddr, paddr, file_size, mem_size, align) if bits == 64 else (
            typ, offset, vaddr, paddr, file_size, mem_size, flags, align)
        struct.pack_into(endian + ('IIQQQQQQ' if bits == 64 else 'IIIIIIII'), data, position, *fields)
    resolved_count = count if extended is None else (extended if extended <= 0x7FFFFFFF else 0)
    meta = dict(bits=bits, little=little, count=resolved_count,
                strict_count=count if extended is None else extended,
                stride=stride, phoff=phoff)
    return bytes(data), meta


def generate():
    cases = []

    def add(name, data, meta, category):
        cases.append(dict(file=name + '.elf', data=data, meta=meta, category=category))

    for bits in (32, 64):
        for little in (True, False):
            tag = f'{bits}-' + ('le' if little else 'be')
            record = 56 if bits == 64 else 32
            for count in (0, 1, 2, 4):
                for high in (False, True):
                    data, meta = base(bits, little, count, high=high)
                    add(f'canonical-{tag}-{count}-{int(high)}', data, meta, 'canonical-and-unsigned')
            # Distinct record boundaries and every byte of one constructor read.
            original, meta = base(bits, little, 2)
            cuts = set(range(128, 128 + record + 1))
            cuts.update((128 + record + 1, 128 + 2 * record - 1, 128 + 2 * record))
            for cut in sorted(cuts):
                add(f'cut-{tag}-{cut}', original[:cut], meta, 'record-truncation')
            for stride in (0, 1, record - 1, record + 1, 0x7FFF, 0x8000, 0xFFFF):
                data, meta = base(bits, little, 2, stride=stride)
                add(f'stride-{tag}-{stride:04x}', data, meta, 'signed-and-noncanonical-stride')
            for phoff in (0, 1, 33, 63, 127, 128, 129, 255, 256, 257):
                data, meta = base(bits, little, 2, phoff=phoff)
                add(f'offset-{tag}-{phoff}', data, meta, 'table-offset-and-overlap')
            # Full-table end is exact, short by one, and longer by one.
            for extra in (-1, 0, 1):
                data, meta = base(bits, little, 2, length=128 + 2 * record + extra)
                add(f'extent-{tag}-{extra:+}', data, meta, 'strict-complete-table')
            for extended in (0, 1, 4097, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
                data, meta = base(bits, little, 2, extended=extended)
                add(f'extended-{tag}-{extended:08x}', data, meta, 'resolved-count-cap')
            # Equality includes every file byte, including the ELF header/table.
            data, meta = base(bits, little, 2, sizes=[100, 156])
            add(f'rewrite-{tag}', data, meta, 'legacy-file-size-rewrite')
    # One full maximum-size table exercises bounded iteration; other resource
    # limit cases stay tiny and never ask the Java reference to allocate >4096.
    data, meta = base(64, True, 4096, length=128 + 4096 * 56)
    add('count-limit-exact-4096', data, meta, 'resolved-count-cap')
    for count in (4097, 32767, 65534):
        data, meta = base(64, True, count)
        add(f'count-limit-{count}', data, meta, 'resolved-count-cap')
    # Java long summation and prefix offsets wrap by bit pattern.
    data, meta = base(64, True, 3, sizes=[U64, 297, 0])
    add('rewrite-wrapping-64-le', data, meta, 'legacy-wrapping-rewrite')
    data, meta = base(64, False, 3, sizes=[U64, U64, 298])
    add('rewrite-wrapping-64-be', data, meta, 'legacy-wrapping-rewrite')
    # Distinguish negative addresses, actual start overflow, final-span safety
    # rejections, and strict unsigned-extent handling.
    for little in (True, False):
        tag = 'le' if little else 'be'
        for distance in (0, 1, 6, 7, 8, 47, 48, 54, 55, 56, 57):
            data, meta = base(64, little, 1, phoff=I64 - distance)
            add(f'signed-end-{tag}-{distance}', data, meta, 'signed-address-safety')
        for offset in (I64 + 1, U64 - 56, U64 - 55, U64):
            data, meta = base(64, little, 1, phoff=offset)
            add(f'unsigned-end-{tag}-{offset:x}', data, meta, 'signed-address-safety')
        data, meta = base(64, little, 2, phoff=I64 - 56)
        add(f'next-record-overflow-{tag}', data, meta, 'signed-address-safety')
    assert len(cases) <= 500, len(cases)
    assert len({row['file'] for row in cases}) == len(cases)
    return cases


def model(case, strict):
    data, m = case['data'], case['meta']
    count, stride, phoff, bits = (m[key] for key in ('count', 'stride', 'phoff', 'bits'))
    if strict:
        count = m['strict_count']
    record = 56 if bits == 64 else 32
    if strict and count:
        if stride != record:
            return dict(accepted=False, error_type='InvalidProgramEntrySize')
        if phoff == 0:
            return dict(accepted=False, error_type='MissingProgramTableOffset')
    if count > 4096:
        return dict(accepted=False, error_type='HeaderCountLimit')
    if strict and count:
        end = phoff + count * stride
        if end > U64:
            return dict(accepted=False, error_type='TableExtentOverflow')
        if end > len(data):
            return dict(accepted=False, error_type='TableOutOfBounds')
    warnings, entries, zero_filled = [], [], 0
    signed_stride = stride if stride < 32768 else stride - 65536
    for index in range(count):
        offset = phoff + index * stride if strict else signed64(phoff) + index * signed_stride
        if not strict:
            if offset < -(1 << 63) or offset > I64:
                return dict(accepted=False, error_type='RecordOffsetOverflow', warnings=warnings,
                            safety=True, java_safety_accepted=False)
            if not warnings and not (offset >= 0 and signed64((offset + signed_stride) & U64) <= len(data)):
                warnings.append(f'{count-index} of {count} program headers are truncated/missing from file')
            if offset < 0:
                return dict(accepted=False, error_type='InvalidRecordOffset', warnings=warnings)
            if offset + record - 1 > I64:
                return dict(accepted=False, error_type='RecordOffsetOverflow', warnings=warnings,
                            safety=True, java_safety_accepted=offset + record - 8 <= I64)
        raw = data[offset:offset+record].ljust(record, b'\0')
        zero_filled += int(offset + record > len(data))
        values = struct.unpack(('<' if m['little'] else '>') + ('IIQQQQQQ' if bits == 64 else 'IIIIIIII'), raw)
        if bits == 64:
            typ, flags, off, va, pa, fs, ms, align = values
        else:
            typ, off, va, pa, fs, ms, flags, align = values
        entries.append(dict(type=typ, flags=flags, raw_offset_hex=f'{off:x}', offset_hex=f'{off:x}',
                            vaddr_hex=f'{va:x}', paddr_hex=f'{pa:x}', filesz_hex=f'{fs:x}',
                            memsz_hex=f'{ms:x}', align_hex=f'{align:x}'))
    rewritten = not strict and sum(int(e['filesz_hex'], 16) for e in entries) & U64 == len(data)
    if rewritten:
        running = 0
        for entry in entries:
            entry['offset_hex'] = f'{running:x}'
            running = (running + int(entry['filesz_hex'], 16)) & U64
    return dict(accepted=True, warnings=warnings, class_bits=bits, header_little_endian=m['little'],
                phnum=count, phentsize=stride, offsets_rewritten=rewritten,
                zero_filled_entries=zero_filled, entries=entries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust', type=Path, default=ROOT / 'target/release/ghidra-elf-segments')
    parser.add_argument('--oracle-source', type=Path, default=ROOT / 'oracle/ElfProgramHeadersOracle.java')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'fixtures').mkdir()
    (output / 'classes').mkdir()
    report = dict(complete=False, commands=[], source_sha256={}, failures=[])

    def run(label, command, allowed=(0,), timeout=90):
        record = dict(label=label, command=list(map(str, command)), timeout_seconds=timeout)
        report['commands'].append(record)
        begin = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
            record.update(exit_code=result.returncode, timed_out=False)
            (output / f'{label}.stdout').write_bytes(result.stdout)
            (output / f'{label}.stderr').write_bytes(result.stderr)
        except subprocess.TimeoutExpired as error:
            record.update(exit_code=None, timed_out=True)
            (output / f'{label}.stdout').write_bytes(error.stdout or b'')
            (output / f'{label}.stderr').write_bytes(error.stderr or b'')
            raise
        finally:
            record['elapsed_seconds'] = time.monotonic() - begin
        if result.returncode not in allowed:
            raise RuntimeError(f'{label}: unexpected process exit {result.returncode}')
        return result

    try:
        sources = [Path(__file__).resolve(), args.oracle_source, ROOT / 'src/lib.rs', ROOT / 'src/main.rs',
                   ROOT.parent / 'src/lib.rs', ROOT / 'Cargo.toml', ROOT / 'Cargo.lock']
        for index, source in enumerate(sources):
            report['source_sha256'][str(source)] = digest(source)
            destination = output / 'sources' / f'{index:02d}-{source.name}'
            destination.parent.mkdir(exist_ok=True)
            shutil.copyfile(source, destination)
        copied_rust = output / 'ghidra-elf-segments'
        shutil.copyfile(args.rust, copied_rust)
        copied_rust.chmod(args.rust.stat().st_mode & 0o777)
        report['rust_sha256'] = digest(copied_rust)
        cases = generate()
        paths = []
        manifest = []
        for case in cases:
            path = output / 'fixtures' / case['file']
            path.write_bytes(case['data'])
            paths.append(path)
            manifest.append({key: value for key, value in case.items() if key != 'data'} |
                            dict(bytes=len(case['data']), sha256=digest(path)))
        save(output / 'manifest.json', manifest)
        jars = sorted(GHIDRA.glob('Ghidra/**/build/libs/*.jar'))
        jars += [Path(line.strip()) for line in (GHIDRA / 'build/libraryDependencies.txt').read_text().splitlines()
                 if line.strip().endswith('.jar') and Path(line.strip()).is_file()]
        jars = list(dict.fromkeys(jars))
        report['jar_sha256'] = {str(path): digest(path) for path in jars}
        classpath = os.pathsep.join(map(str, jars))
        run('javac', [JAVA / 'javac', '-cp', classpath, '-d', output / 'classes', args.oracle_source])
        oracle_class = args.oracle_source.stem
        java = run('java', [JAVA / 'java', '-Xmx256m', '-cp', str(output / 'classes') + os.pathsep + classpath,
                            oracle_class, *paths])
        reference = json.loads(java.stdout)
        if len(reference) != len(cases):
            raise RuntimeError('Java output cardinality differs from frozen fixture set')
        if [row['file'] for row in reference] != [case['file'] for case in cases]:
            raise RuntimeError('Java output reordered, missing or duplicated fixture names')
        java_map = {row['file']: row for row in reference}
        matches, strict_matches, safety = [], [], []
        for strict in (False, True):
            label = 'rust-strict' if strict else 'rust-compatible'
            result = run(label, [copied_rust, '--strict' if strict else '--compatible', *paths], allowed=(0, 1))
            actual = json.loads(result.stdout)
            if len(actual) != len(cases) or [row['file'] for row in actual] != [case['file'] for case in cases]:
                raise RuntimeError(f'{label} output cardinality/order invalid')
            if result.returncode != int(any(not row['accepted'] for row in actual)):
                raise RuntimeError(f'{label} status contradicts accepted flags')
            for case, observed in zip(cases, actual, strict=True):
                expected = model(case, strict)
                keys = ['accepted', *(COMMON if expected['accepted'] else ('error_type',))]
                if expected['accepted'] or 'warnings' in expected:
                    keys.append('warnings')
                if expected['accepted']:
                    keys.append('zero_filled_entries')
                differences = {key: dict(expected=expected.get(key), actual=observed.get(key))
                               for key in keys if expected.get(key) != observed.get(key)}
                if differences:
                    report['failures'].append(dict(file=case['file'], policy=label, model_differences=differences))
                if strict:
                    if not differences:
                        strict_matches.append(case['file'])
                    continue
                original = java_map[case['file']]
                if expected.get('safety'):
                    if original['accepted'] != expected['java_safety_accepted']:
                        report['failures'].append(dict(file=case['file'], policy=label,
                                                       java_safety_acceptance=dict(expected=expected['java_safety_accepted'],
                                                                                   actual=original['accepted'])))
                    if expected['java_safety_accepted']:
                        safety.append(dict(file=case['file'], expected_rust=expected['error_type'],
                                           java_accepted=original['accepted'], java_error=original.get('error_type'),
                                           passed=not differences))
                        continue
                parity_keys = ['accepted', 'warnings', *(COMMON if original['accepted'] else ())]
                parity_differences = {key: dict(java=original.get(key), rust=observed.get(key))
                                      for key in parity_keys if original.get(key) != observed.get(key)}
                if parity_differences:
                    report['failures'].append(dict(file=case['file'], policy=label,
                                                   java_differences=parity_differences))
                elif not differences:
                    matches.append(case['file'])
        report.update(fixture_count=len(cases), parity_case_count=len(matches), parity_cases=matches,
                      strict_case_count=len(strict_matches), strict_cases=strict_matches,
                      safety_exception_count=len(safety), safety_exceptions=safety)
        report['source_unchanged'] = all(digest(Path(path)) == sha for path, sha in report['source_sha256'].items())
        report['binary_unchanged'] = digest(args.rust) == report['rust_sha256']
        report['complete'] = not report['failures'] and report['source_unchanged'] and report['binary_unchanged']
        if not report['complete']:
            raise RuntimeError('Independent edge validation failed; see summary.json')
        print(f'PASS: {len(matches)} Java parity; {len(safety)} separate safety exceptions; '
              f'{len(strict_matches)} strict-policy expectations')
    except BaseException as error:
        report['error'] = dict(type=type(error).__name__, message=str(error))
        raise
    finally:
        save(output / 'summary.json', report)
        print(output / 'summary.json', flush=True)


if __name__ == '__main__':
    main()
