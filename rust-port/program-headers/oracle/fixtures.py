"""Deterministic, bounded ELF program-header fixtures; no executable payloads.

Generation only creates a fresh directory. Every byte and intended policy edge is
recorded before Java or Rust sees the corpus. Does not touch the earlier header lab.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct


def header(bits=64, endian='<', **changes):
    fields = dict(type=2, machine=62 if bits == 64 else 3, version=1,
                  entry=0x12345678, phoff=128, shoff=0, flags=0x80000001,
                  ehsize=64 if bits == 64 else 52, phentsize=56 if bits == 64 else 32,
                  phnum=1, shentsize=64 if bits == 64 else 40, shnum=0, shstrndx=0)
    fields.update(changes)
    ident = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2, 1, 0, 0]) + bytes(7)
    return ident + struct.pack(endian + ('HHIQQQIHHHHHH' if bits == 64 else 'HHIIIIIHHHHHH'), *fields.values())


def record(bits=64, endian='<', **changes):
    values = dict(type=1, flags=5, offset=0x258, vaddr=0x401000,
                  paddr=0x501000, filesz=7, memsz=11, align=4096)
    values.update(changes)
    fields = ('type', 'flags', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'align') if bits == 64 else (
        'type', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'flags', 'align')
    return struct.pack(endian + ('IIQQQQQQ' if bits == 64 else 'IIIIIIII'), *(values[x] for x in fields))


def section0(bits, endian, count, kind=0):
    return struct.pack(endian + ('IIQQQQIIQQ' if bits == 64 else 'IIIIIIIIII'),
                       0, kind, 0, 0, 0, 0, 0, count, 0, 0)


def image(bits, endian, count=1, stride=None, phoff=128, records=None, **changes):
    size = 56 if bits == 64 else 32
    if stride is None:
        stride = size
    fields = dict(phnum=count, phentsize=stride, phoff=phoff)
    fields.update(changes)
    result = bytearray(header(bits, endian, **fields))
    if records is None:
        records = [record(bits, endian, offset=0x258 + 16 * i, filesz=i + 7) for i in range(count)]
    # Data layout is chosen independently of the parser's signed declared stride.
    if records and phoff < (1 << 20):
        spacing = stride if 0 < stride < 256 else size
        for i, value in enumerate(records):
            start = phoff + i * spacing
            if len(result) < start + len(value):
                result.extend(bytes(start + len(value) - len(result)))
            result[start:start + len(value)] = value
    return bytes(result)


def generate(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    cases = []

    def save(name, data, group, expected_difference=None, strict_note=None):
        name += '.elf'
        (output / name).write_bytes(data)
        cases.append(dict(file=name, group=group, length=len(data), sha256=hashlib.sha256(data).hexdigest(),
                          expected_difference=expected_difference, strict_note=strict_note))

    for bits in (32, 64):
        for endian, label in (('<', 'le'), ('>', 'be')):
            tag = f'{bits}-{label}'
            size = 56 if bits == 64 else 32
            for count in (0, 1, 2, 3, 7, 16, 32):
                save(f'canonical-{tag}-{count}', image(bits, endian, count=count), 'canonical')
            for stride in (0, 1, size - 1, size + 1, size + 8, 0x7fff, 0x8000, 0xffff):
                data = image(bits, endian, count=3, stride=stride)
                save(f'stride-{tag}-{stride}', data, 'declared-stride',
                     strict_note='Strict requires canonical declared stride.')
            complete = image(bits, endian, count=3)
            for length in (0, 3, 4, 16, 33, 34, 51, 52, 63, 127, 128, 129, 128 + size - 1, 128 + size, len(complete) - 1):
                save(f'truncated-{tag}-{length}', complete[:length], 'truncation',
                     strict_note='Strict rejects truncated required header/table bytes.')
            for phoff in (0, 16, 64, 4096):
                save(f'offset-{tag}-{phoff}', image(bits, endian, phoff=phoff, records=[]), 'table-position')
            high = (1 << bits) - 1
            for field in ('offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'align'):
                save(f'high-{tag}-{field}', image(bits, endian, records=[record(bits, endian, **{field: high}, type=0xffffffff, flags=0x80000001)]), 'unsigned-fields')
            # Real parser's malformed-file rewrite, including wrapping uint64 sums.
            total_len = 128 + 2 * size
            for mode, sizes in [('equal', (17, total_len - 17)), ('near', (17, total_len - 16)), ('zero', (0, total_len))]:
                data = image(bits, endian, count=2, records=[record(bits, endian, offset=0x123456, filesz=sizes[0]), record(bits, endian, offset=0xabcdef, filesz=sizes[1])])
                save(f'heuristic-{tag}-{mode}', data, 'legacy-offset-rewrite',
                     strict_note='Strict preserves original offsets instead of applying legacy rewrite.')
            if bits == 64:
                data = image(bits, endian, count=2, records=[record(bits, endian, filesz=(1 << 64) - 3), record(bits, endian, filesz=total_len + 3)])
                save(f'heuristic-{tag}-wrapping-sum', data, 'legacy-offset-rewrite',
                     strict_note='Strict preserves raw offsets; compatibility matches wrapping long sum.')
            for count, kind, variant in [(2, 0, 'valid'), (0x80000000, 0, 'negative-count'), (2, 1, 'nonnull'), (4096, 0, 'cap'), (4097, 0, 'over-cap')]:
                data = bytearray(image(bits, endian, phnum=0xffff, shoff=64, count=2))
                s0 = section0(bits, endian, count, kind)
                data[64:64 + len(s0)] = s0
                save(f'extended-{tag}-{variant}', data, 'extended-count',
                     strict_note='Oracle and Rust enforce wrapper resource cap 4096 before the table loop.')
            save(f'extended-{tag}-missing', header(bits, endian, phnum=0xffff, shoff=4096), 'extended-count')
            data = bytearray(image(bits, endian))
            data[5] = 0 if endian == '<' else 2
            save(f'encoding-{tag}', data, 'encoding-compatibility')
            data = bytearray(image(bits, endian)); data[4] = 3
            save(f'invalid-class-{tag}', data, 'invalid-header')
            save(f'bad-magic-{tag}', b'BAD!' + image(bits, endian)[4:], 'invalid-header')
            # PRE trailer must not silently transform the raw program-header fields.
            save(f'prelink-trailer-{tag}', image(bits, endian) + struct.pack(endian + 'I', 0x10000000) + b'PRE ', 'raw-address-scope')

    # Java long record-pointer wrap is intentionally rejected by Rust. Keep these
    # cases distinct from ordinary compatibility parity, even when both reject.
    for endian, label in (('<', 'le'), ('>', 'be')):
        for distance in (0, 7, 31, 47, 48, 54, 55, 56):
            phoff = (1 << 63) - 1 - distance
            save(f'checked-record-overflow-64-{label}-{distance}', header(64, endian, phoff=phoff, phnum=1),
                 'intentional-signed-overflow',
                 expected_difference=dict(java_accepted=True, rust_error='RecordOffsetOverflow') if distance in (48, 54) else None,
                 strict_note='Rust deliberately rejects signed record-address overflow; final long reads starting at or below LONG_MAX may cross it in Java.')
        save(f'checked-stride-overflow-64-{label}', header(64, endian, phoff=1 << 63, phentsize=0xffff, phnum=2),
             'intentional-signed-overflow',
             strict_note='Both reject the negative first record address before any later signed-stride wrap can occur.')

    cases.sort(key=lambda x: x['file'])
    manifest = dict(schema=1, resource_bound_program_headers=4096,
                    purpose='Original private ELF program-header parser parity; no payload execution or loader adapters.',
                    cases=cases, groups={group: sum(c['group'] == group for c in cases) for group in sorted({c['group'] for c in cases})})
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = generate(args.output)
    print(f"Generated {len(manifest['cases'])} immutable program-header fixtures at {args.output}")
