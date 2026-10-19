"""Deterministic, bounded ELF section-header fixtures; no executable payloads.

Generation only creates a fresh directory. Every byte and intended policy edge is
recorded before Java or Rust sees the corpus.
"""
from pathlib import Path
import argparse
import hashlib
import json
import random
import struct

STRTAB_OFFSET = 0x100
DATA_OFFSET = 0x200
SHOFF = 0x400
LONG_MAX = (1 << 63) - 1

# Names placed in the standard string table, in order.
NAMES = ['', '.text', '.bss', '.symtab_shndx', '.debug_info', '.shstrtab']


def strtab(names):
    data, offsets = bytearray(), []
    for name in names:
        offsets.append(len(data))
        data += name + b'\0'
    return bytes(data), offsets


STANDARD_STRTAB, STANDARD_OFFSETS = strtab([n.encode() for n in NAMES])


def header(bits=64, endian='<', **changes):
    fields = dict(type=1, machine=62 if bits == 64 else 3, version=1,
                  entry=0, phoff=0, shoff=SHOFF, flags=0,
                  ehsize=64 if bits == 64 else 52, phentsize=56 if bits == 64 else 32,
                  phnum=0, shentsize=64 if bits == 64 else 40, shnum=0, shstrndx=0)
    fields.update(changes)
    ident = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2, 1, 0, 0]) + bytes(7)
    return ident + struct.pack(endian + ('HHIQQQIHHHHHH' if bits == 64 else 'HHIIIIIHHHHHH'), *fields.values())


def shdr(bits=64, endian='<', **changes):
    values = dict(name=0, type=0, flags=0, addr=0, offset=0, size=0, link=0, info=0, align=0, entsize=0)
    values.update(changes)
    return struct.pack(endian + ('IIQQQQIIQQ' if bits == 64 else 'IIIIIIIIII'), *values.values())


def chdr(bits, endian, kind=1, size=0x1000, align=1):
    if bits == 64:
        return struct.pack(endian + 'IIQQ', kind, 0, size, align)
    return struct.pack(endian + 'III', kind, size, align)


def standard_sections(bits, endian, extended_index=False, compressed=None):
    """Null, .text, .bss, optional .symtab_shndx, .debug_info, .shstrtab."""
    o = STANDARD_OFFSETS
    rows = [dict(),
            dict(name=o[1], type=1, flags=6, addr=0x401000, offset=DATA_OFFSET, size=0x20, align=16),
            dict(name=o[2], type=8, flags=3, addr=0x402000, offset=DATA_OFFSET + 0x20, size=0x100, align=32)]
    if extended_index:
        rows.append(dict(name=o[3], type=18, offset=DATA_OFFSET + 0x20, size=0x10, link=0, align=4, entsize=4))
    debug = dict(name=o[4], type=1, flags=0x800, offset=DATA_OFFSET + 0x40, size=0x40, align=1)
    debug.update(compressed or {})
    rows.append(debug)
    rows.append(dict(name=o[5], type=3, offset=STRTAB_OFFSET, size=len(STANDARD_STRTAB), align=1))
    return rows


def image(bits, endian, sections=None, stride=None, shoff=SHOFF, strings=STANDARD_STRTAB, payload=None,
          shstrndx=None, place_records=True, **changes):
    size = 64 if bits == 64 else 40
    if sections is None:
        sections = standard_sections(bits, endian)
    if stride is None:
        stride = size
    if shstrndx is None:
        shstrndx = len(sections) - 1 if sections else 0
    fields = dict(shnum=len(sections), shentsize=stride, shoff=shoff, shstrndx=shstrndx)
    fields.update(changes)
    result = bytearray(header(bits, endian, **fields))
    result.extend(bytes(SHOFF - len(result)))
    result[STRTAB_OFFSET:STRTAB_OFFSET + len(strings)] = strings
    if payload is None:
        payload = b'\x90' * 0x20 + bytes(0x20) + chdr(bits, endian) + b'\x78\x9c' + bytes(0x40)
    result[DATA_OFFSET:DATA_OFFSET + len(payload)] = payload
    # Data layout is chosen independently of the parser's signed declared stride.
    if place_records and sections and shoff < (1 << 20):
        spacing = stride if 0 < stride < 256 else size
        for i, values in enumerate(sections):
            record = shdr(bits, endian, **values)
            start = shoff + i * spacing
            if len(result) < start + len(record):
                result.extend(bytes(start + len(record) - len(result)))
            result[start:start + len(record)] = record
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
            size = 64 if bits == 64 else 40
            std = standard_sections(bits, endian)

            # Canonical tables of several sizes and string-table choices.
            save(f'canonical-{tag}', image(bits, endian), 'canonical')
            save(f'canonical-{tag}-extended-index', image(bits, endian, standard_sections(bits, endian, True)), 'canonical')
            save(f'canonical-{tag}-empty', image(bits, endian, [], shoff=0), 'canonical')
            save(f'canonical-{tag}-null-only', image(bits, endian, [dict()], shstrndx=0), 'canonical')
            save(f'canonical-{tag}-no-strtab', image(bits, endian, shstrndx=0), 'canonical',
                 strict_note='All names fall back to SECTION<index>.')
            many = [dict()] + [dict(name=STANDARD_OFFSETS[1], type=1, offset=DATA_OFFSET, size=i)
                               for i in range(1, 299)] + [std[-1]]
            save(f'canonical-{tag}-300', image(bits, endian, many), 'canonical')

            # Declared stride: Java uses a signed short, the record read is fixed.
            for stride in (0, 1, size - 1, size + 1, size + 8, 0x7fff, 0x8000, 0xffff):
                save(f'stride-{tag}-{stride}', image(bits, endian, stride=stride), 'declared-stride',
                     strict_note='Strict requires the canonical declared stride.')

            # Truncation inside the table and around the header.
            complete = image(bits, endian)
            for length in (0, 3, 4, 16, 33, 34, 51, 52, 63, 64, SHOFF, SHOFF + 1, SHOFF + size - 1,
                           SHOFF + size, SHOFF + 2 * size + 5, len(complete) - 1):
                save(f'truncated-{tag}-{length}', complete[:length], 'truncation',
                     strict_note='Strict rejects truncated required header/table bytes.')

            # Table position.
            for shoff in (16, 64, 0x10000):
                save(f'offset-{tag}-{shoff}', image(bits, endian, shoff=shoff, place_records=shoff != 0x10000),
                     'table-position')
            if bits == 64:
                for shoff in (1 << 63, (1 << 64) - 1):
                    save(f'offset-{tag}-negative-{shoff:x}', image(bits, endian, shoff=shoff), 'table-position',
                         strict_note='Java throws reading a negative record index; Rust reports InvalidRecordOffset.')
            save(f'offset-{tag}-negative-stride', image(bits, endian, shoff=size, stride=0x10000 - 2 * size),
                 'table-position')

            # Unsigned field widths.
            high = (1 << bits) - 1
            for field in ('flags', 'addr', 'offset', 'size', 'align', 'entsize'):
                rows = [dict(), dict(name=1, type=0xffffffff, **{field: high}, link=0xffffffff, info=0xffffffff),
                        std[-1]]
                save(f'high-{tag}-{field}', image(bits, endian, rows), 'unsigned-fields')

            # Section-name lookup: Ghidra ignores the string table's size.
            def names_case(label, name_index, strings=STANDARD_STRTAB, **extra):
                rows = [dict(), dict(name=name_index, type=1, offset=DATA_OFFSET, size=0x20), std[-1]]
                save(f'name-{tag}-{label}', image(bits, endian, rows, strings=strings, **extra), 'section-names')

            complete_len = len(complete)
            names_case('past-table-size', len(STANDARD_STRTAB) + 2)
            names_case('empty', 0)
            names_case('last-byte', complete_len - 1 - STRTAB_OFFSET)
            names_case('at-eof', complete_len - STRTAB_OFFSET)
            names_case('past-eof', complete_len + 100 - STRTAB_OFFSET)
            names_case('high-bit', 0x80000000)
            names_case('all-ones', 0xffffffff)
            names_case('max-int', 0x7fffffff)
            for label, raw in [('whitespace', b' .text\t '), ('latin1', 'été'.encode()),
                               ('cjk', '日本'.encode()), ('emoji', '\U0001f600'.encode()),
                               ('bad-ff', b'\xff'), ('bad-lead', b'\xc3'), ('bad-two-of-three', b'\xe2\x82'),
                               ('bad-three-of-four', b'\xf0\x9f\x98'), ('surrogate', b'\xed\xa0\x80'),
                               ('overlong-nul', b'\xc0\x80'), ('five-byte', b'\xf8\x88\x80\x80\x80'),
                               ('above-max', b'\xf4\x90\x80\x80'), ('mixed', b'ok\xffok\xe2\x82(x'),
                               ('continuation-run', b'\x80\x80\x80a'), ('control', b'\x01\x1f\x7f'),
                               ('surrogate-tail', b'\xed\xa0'), ('surrogate-bad-third', b'\xed\xa0A'),
                               ('overlong-three', b'\xe0\x80\x80'), ('overlong-four', b'\xf0\x80\x80\x80'),
                               ('four-tail', b'\xf4\x8f'), ('four-tail-bad', b'\xf0\x9fA'),
                               ('f5', b'\xf5\x80\x80\x80')]:
                names_case(f'utf8-{label}', len(STANDARD_STRTAB), strings=STANDARD_STRTAB + raw + b'\0')
            # Unterminated name reaching EOF: put the table first and the strings last.
            rows = [dict(), dict(name=1, type=1, offset=DATA_OFFSET, size=0x20),
                    dict(name=7, type=3, offset=SHOFF + 3 * size, size=12)]
            base = image(bits, endian, rows)[:SHOFF + 3 * size]
            save(f'name-{tag}-unterminated-eof', base + b'\0.text\0.shstr', 'section-names')
            save(f'name-{tag}-strtab-at-eof', base, 'section-names')
            for label, values in [('nobits', dict(type=8)), ('offset-past-eof', dict(offset=0x100000)),
                                  ('size-past-eof', dict(size=0x100000))]:
                rows = std[:-1] + [dict(std[-1], **values)]
                save(f'strtab-{tag}-{label}', image(bits, endian, rows), 'section-names')
            rows = std[:-1] + [dict(std[-1], offset=high)]
            save(f'strtab-{tag}-invalid-offset', image(bits, endian, rows), 'section-names',
                 strict_note='Ghidra treats this string-table offset as invalid.')
            if bits == 64:
                for label, offset in [('negative', 1 << 63), ('near-max', LONG_MAX - 4)]:
                    rows = std[:-1] + [dict(std[-1], offset=offset)]
                    save(f'strtab-{tag}-{label}', image(bits, endian, rows), 'section-names')
            for index in (0, len(std), 0xfeff):
                save(f'strtab-{tag}-index-{index}', image(bits, endian, shstrndx=index), 'section-names',
                     strict_note='Strict rejects a string-table index outside the table.')
            save(f'strtab-{tag}-index-self-null', image(bits, endian, shstrndx=0), 'section-names')

            # SHF_COMPRESSED probe of the default load adapter.
            def compressed_case(label, payload_chdr=None, **values):
                payload = b'\x90' * 0x20 + bytes(0x20) + (payload_chdr if payload_chdr is not None
                                                           else chdr(bits, endian)) + bytes(0x40)
                save(f'compressed-{tag}-{label}', image(bits, endian, standard_sections(bits, endian, compressed=values),
                                                        payload=payload), 'compression')

            compressed_case('valid')
            for kind in (0, 2, 0x60000000, 0xffffffff):
                compressed_case(f'type-{kind:x}', chdr(bits, endian, kind=kind))
            compressed_case('max-size', chdr(bits, endian, size=high, align=high))
            compressed_case('alloc', flags=0x802)
            compressed_case('nobits', type=8)
            hsize = 24 if bits == 64 else 12
            for length in (0, 1, hsize - 1, hsize):
                compressed_case(f'size-{length}', size=length)
            compressed_case('ends-at-eof', size=len(complete) - (DATA_OFFSET + 0x40))
            compressed_case('past-eof', size=len(complete) - (DATA_OFFSET + 0x40) + 1)
            compressed_case('offset-past-eof', offset=len(complete) + 8)
            compressed_case('with-other-flags', flags=0x800 | 0x30 | 0x100)
            if bits == 64:
                compressed_case('offset-negative', offset=1 << 63)
                compressed_case('size-negative', size=1 << 63)
                compressed_case('end-wraps', offset=DATA_OFFSET + 0x40, size=(1 << 63) - 1)

            # Extended numbering through section zero.
            for label, s0, raw in [('count', dict(size=5), dict(shnum=0)),
                                   ('count-zero', dict(size=0), dict(shnum=0)),
                                   ('strndx', dict(link=4), dict(shstrndx=0xffff)),
                                   ('both', dict(size=5, link=4), dict(shnum=0, shstrndx=0xffff)),
                                   ('nonnull', dict(type=1, size=5, link=4), dict(shnum=0, shstrndx=0xffff)),
                                   ('reserved-count', dict(size=5), dict(shnum=0xff00)),
                                   ('negative-count', dict(size=0x80000000), dict(shnum=0))]:
                rows = [dict(std[0], **s0)] + std[1:]
                save(f'extended-{tag}-{label}', image(bits, endian, rows, **raw), 'extended-count',
                     strict_note='Strict rejects reserved counts and non-null section zero when needed.')

            # Header-level recovery inherited from the first component.
            data = bytearray(image(bits, endian))
            data[5] = 0 if endian == '<' else 3
            save(f'encoding-{tag}', data, 'encoding-compatibility')
            data = bytearray(image(bits, endian))
            data[4] = 3
            save(f'invalid-class-{tag}', data, 'invalid-header')
            save(f'bad-magic-{tag}', b'BAD!' + image(bits, endian)[4:], 'invalid-header')
            # A PRE trailer must not silently transform raw section addresses.
            save(f'prelink-trailer-{tag}', image(bits, endian) + struct.pack(endian + 'I', 0x10000000) + b'PRE ',
                 'raw-address-scope')

    # Section records decode with the actual header order, but Ghidra reads the
    # compression header with the declared EI_DATA order.
    for bits in (32, 64):
        data = bytearray(image(bits, '<'))
        data[5] = 2  # declared big-endian; e_type/e_version still look little-endian
        save(f'compressed-{bits}-declared-be-actual-le', data, 'compression')
        data = bytearray(image(bits, '<'))
        data[5] = 0
        save(f'compressed-{bits}-invalid-data-le', data, 'compression')

    # Randomized names compare Java's UTF-8 replacement rules byte for byte.
    rng = random.Random(0x5EC7)
    alphabet = (list(range(0x20, 0x7f)) + list(range(0x80, 0xc0)) * 2 +
                [0xc0, 0xc1, 0xc2, 0xc3, 0xdf, 0xe0, 0xe1, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf4, 0xf5, 0xf7, 0xf8, 0xff] * 6)
    for seed in range(4):
        names = [bytes(rng.choice(alphabet) for _ in range(rng.randint(1, 10))) for _ in range(400)]
        strings, offsets = strtab([b''] + names + [b'.shstrtab'])
        rows = [dict()] + [dict(name=offsets[i + 1], type=1) for i in range(len(names))]
        rows.append(dict(name=offsets[-1], type=3, offset=STRTAB_OFFSET, size=len(strings)))
        shoff = STRTAB_OFFSET + len(strings) + 8
        save(f'name-64-le-utf8-random-{seed}', image(64, '<', rows, shoff=shoff, strings=strings, payload=b''),
             'section-names')

    # Resource bound, enforced by both the oracle and Rust before the table loop.
    for label, count in [('cap', 65536), ('over-cap', 65537)]:
        rows = [dict(size=count)]
        save(f'extended-64-le-{label}', image(64, '<', rows, shnum=0, shstrndx=0), 'resource-bound',
             strict_note='Wrapper cap of 65536 section headers; zero-filled records past EOF.')

    # Java long record-pointer wrap is intentionally rejected by Rust. Ghidra
    # fails only when a field read starts past LONG_MAX (offset + 56); Rust
    # rejects when any record byte would (offset + 63).
    for endian, label in (('<', 'le'), ('>', 'be')):
        for distance in (0, 6, 7, 54, 55, 58, 61, 62, 63):
            shoff = LONG_MAX - 1 - distance
            differs = 55 <= distance <= 61
            save(f'checked-record-overflow-64-{label}-{distance}', header(64, endian, shoff=shoff, shnum=1),
                 'intentional-signed-overflow',
                 expected_difference=dict(java_accepted=True, rust_error='RecordOffsetOverflow') if differs else None,
                 strict_note='Rust deliberately rejects signed record-address overflow.')

    cases.sort(key=lambda x: x['file'])
    manifest = dict(schema=1, resource_bound_section_headers=65536,
                    purpose='Original public ELF section-header parser parity; no decompression or loader adapters.',
                    cases=cases, groups={group: sum(c['group'] == group for c in cases) for group in sorted({c['group'] for c in cases})})
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = generate(args.output)
    print(f"Generated {len(manifest['cases'])} immutable section-header fixtures at {args.output}")
