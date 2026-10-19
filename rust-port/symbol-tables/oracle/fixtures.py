"""Deterministic, bounded ELF string/symbol-table fixtures; no executable payloads.

Generation only creates a fresh directory. Every byte and intended policy edge is
recorded before Java or Rust sees the corpus.
"""
from pathlib import Path
import argparse
import hashlib
import json
import random
import struct

LONG_MAX = (1 << 63) - 1
SHSTRTAB = 0x80
STRTAB = 0x200
SYMTAB = 0x400
DYNSTR = 0x800
DYNSYM = 0x880
SHNDX = 0x980
SHOFF = 0xa00

SECTION_NAMES = ['', '.text', '.data', '.symtab', '.strtab', '.dynsym', '.dynstr', '.symtab_shndx',
                 '.shstrtab', '.other']


def strtab(names):
    data, offsets = bytearray(), {}
    for name in names:
        offsets[name] = len(data)
        data += (name if isinstance(name, bytes) else name.encode()) + b'\0'
    return bytes(data), offsets


SHSTR, SHNAME = strtab(SECTION_NAMES)
SYMBOL_NAMES = ['', 'crt.c', 'main', 'helper', 'counter', ' padded\t', 'weak_fn', 'tls_var']
STRINGS, SYMNAME = strtab(SYMBOL_NAMES)
DYNSTRINGS, DYNNAME = strtab(['', 'puts', 'libc.so.6'])


def header(bits, endian, **changes):
    fields = dict(type=1, machine=62 if bits == 64 else 3, version=1, entry=0, phoff=0, shoff=SHOFF,
                  flags=0, ehsize=64 if bits == 64 else 52, phentsize=56 if bits == 64 else 32,
                  phnum=0, shentsize=64 if bits == 64 else 40, shnum=0, shstrndx=0)
    fields.update(changes)
    ident = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2, 1, 0, 0]) + bytes(7)
    return ident + struct.pack(endian + ('HHIQQQIHHHHHH' if bits == 64 else 'HHIIIIIHHHHHH'), *fields.values())


def shdr(bits, endian, name='', **changes):
    values = dict(name=SHNAME.get(name, 0) if isinstance(name, str) else name, type=0, flags=0, addr=0,
                  offset=0, size=0, link=0, info=0, align=0, entsize=0)
    values.update(changes)
    return struct.pack(endian + ('IIQQQQIIQQ' if bits == 64 else 'IIIIIIIIII'), *values.values())


def sym(bits, endian, name=0, info=0, other=0, shndx=0, value=0, size=0):
    if bits == 64:
        return struct.pack(endian + 'IBBHQQ', name, info, other, shndx, value, size)
    return struct.pack(endian + 'IIIBBH', name, value, size, info, other, shndx)


def standard_symbols(bits, endian):
    n = SYMNAME
    rows = [dict(),
            dict(name=n['crt.c'], info=4, shndx=0xfff1),
            dict(info=3, shndx=1), dict(info=3, shndx=2),
            dict(name=n['main'], info=0x12, shndx=1, value=0x401000, size=0x20),
            dict(name=n['helper'], info=0x02, other=2, shndx=1, value=0x401020, size=8),
            dict(name=n['counter'], info=0x11, shndx=2, value=0x402000, size=4),
            dict(name=n[' padded\t'], info=0x11, shndx=2, value=0x402004, size=4),
            dict(name=n['weak_fn'], info=0x22, shndx=0),
            dict(name=n['tls_var'], info=0x16, shndx=2, value=0x10, size=8)]
    return rows


def entsize(bits):
    return 24 if bits == 64 else 16


def image(bits, endian, symbols=None, symtab=None, strings=STRINGS, dynsym=True, shndx=None,
          extra_sections=(), blobs=(), truncate=None, symbols_at=SYMTAB, **header_changes):
    """Sections: 0 null, 1 .text, 2 .data, 3 .symtab, 4 .strtab, 5 .dynsym, 6 .dynstr,
    7 .shstrtab, then extra_sections; .symtab_shndx appended when given."""
    if symbols is None:
        symbols = standard_symbols(bits, endian)
    symbol_bytes = b''.join(sym(bits, endian, **row) for row in symbols)
    table = dict(name='.symtab', type=2, offset=SYMTAB, size=len(symbol_bytes), link=4, info=4,
                 align=8, entsize=entsize(bits))
    table.update(symtab or {})
    dyn_bytes = sym(bits, endian) + sym(bits, endian, name=DYNNAME['puts'], info=0x12)
    sections = [dict(), dict(name='.text', type=1, flags=6, addr=0x401000, offset=0x300, size=0x40),
                dict(name='.data', type=1, flags=3, addr=0x402000, offset=0x340, size=0x20),
                table, dict(name='.strtab', type=3, offset=STRTAB, size=len(strings)),
                dict(name='.dynsym', type=11 if dynsym else 1, flags=2, addr=0x400880, offset=DYNSYM,
                     size=len(dyn_bytes), link=6, info=1, entsize=entsize(bits)),
                dict(name='.dynstr', type=3, flags=2, addr=0x400800, offset=DYNSTR, size=len(DYNSTRINGS)),
                dict(name='.shstrtab', type=3, offset=SHSTRTAB, size=len(SHSTR))]
    sections += list(extra_sections)
    if shndx is not None:
        entries, values = shndx
        payload = struct.pack(endian + 'I' * len(entries), *entries)
        index_section = dict(name='.symtab_shndx', type=18, offset=SHNDX, size=len(payload), link=3,
                             align=4, entsize=4)
        index_section.update(values)
        sections.append(index_section)
        if index_section['offset'] < (1 << 20):
            blobs = list(blobs) + [(index_section['offset'], payload)]
    record = 64 if bits == 64 else 40
    data = bytearray(header(bits, endian, shnum=len(sections), shstrndx=7, **header_changes))
    data.extend(bytes(SHOFF + record * len(sections) - len(data)))
    for offset, blob in [(SHSTRTAB, SHSTR), (STRTAB, strings), (symbols_at, symbol_bytes),
                         (DYNSTR, DYNSTRINGS), (DYNSYM, dyn_bytes), (0x300, b'\xc3' * 0x40), *blobs]:
        if len(data) < offset + len(blob):
            data.extend(bytes(offset + len(blob) - len(data)))
        data[offset:offset + len(blob)] = blob
    for i, values in enumerate(sections):
        data[SHOFF + record * i:SHOFF + record * (i + 1)] = shdr(bits, endian, **values)
    return bytes(data[:truncate] if truncate is not None else data)


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
            size = entsize(bits)
            std = standard_symbols(bits, endian)
            n = SYMNAME

            save(f'canonical-{tag}', image(bits, endian), 'canonical')
            save(f'canonical-{tag}-no-dynsym', image(bits, endian, dynsym=False), 'canonical')
            save(f'canonical-{tag}-null-only', image(bits, endian, [dict()]), 'canonical')
            save(f'canonical-{tag}-empty', image(bits, endian, []), 'canonical')
            many = [dict(name=n['main'], info=0x12, shndx=1, value=0x401000 + i) for i in range(200)]
            save(f'canonical-{tag}-200', image(bits, endian, many, symtab=dict(offset=0x2000), symbols_at=0x2000),
                 'canonical')
            save(f'canonical-{tag}-no-sections', header(bits, endian, shoff=0), 'canonical')

            # Entry size and count arithmetic.
            for es in (0, 1, size - 1, size + 8, 0x1000, (1 << bits) - 1):
                save(f'entsize-{tag}-{es:x}', image(bits, endian, symtab=dict(entsize=es)), 'entry-size',
                     strict_note='Strict requires the canonical entry size.')
            for label2, extra in [('remainder', 5), ('short', -3)]:
                rows = b''.join(sym(bits, endian, **r) for r in std)
                save(f'size-{tag}-{label2}', image(bits, endian, symtab=dict(size=len(rows) + extra)), 'entry-size')
            if bits == 64:
                for value in (1 << 63, (1 << 64) - size, (1 << 63) + 24 * 3):
                    save(f'size-{tag}-negative-{value:x}', image(bits, endian, symtab=dict(size=value)), 'entry-size',
                         strict_note='Java long division gives a negative or zero count.')
                save(f'size-{tag}-negative-entsize', image(bits, endian, symtab=dict(entsize=(1 << 64) - 24)),
                     'entry-size')

            # Table position.
            full = image(bits, endian)
            for cut in (SYMTAB + 1, SYMTAB + size * 3 + 2, DYNSTR - 1):
                save(f'truncated-{tag}-symtab-past-eof-{cut:x}',
                     image(bits, endian, symtab=dict(offset=len(full) + cut)), 'table-position')
            high = (1 << bits) - 1
            save(f'offset-{tag}-invalid', image(bits, endian, symtab=dict(offset=high)), 'table-position',
                 strict_note='Ghidra skips symbol tables with invalid offsets.')
            if bits == 64:
                save(f'offset-{tag}-negative', image(bits, endian, symtab=dict(offset=1 << 63)), 'table-position')
                for distance in (0, 15, 16, 17, 30, 40, 48):
                    save(f'offset-{tag}-near-max-{distance}',
                         image(bits, endian, symtab=dict(offset=LONG_MAX - distance)), 'table-position',
                         strict_note='Java fails when a field read starts past Long.MAX_VALUE.')

            # sh_link and string-table lookup by file offset.
            for link in (0, 1, 7, 8, 0x7fffffff, 0xffffffff):
                save(f'link-{tag}-{link:x}', image(bits, endian, symtab=dict(link=link)), 'string-table-link',
                     strict_note='Strict requires a linked SHT_STRTAB section.')
            alias = dict(name='.other', type=1, offset=STRTAB, size=4)
            save(f'link-{tag}-offset-alias', image(bits, endian, symtab=dict(link=8), extra_sections=[alias]),
                 'string-table-link', strict_note='Ghidra finds the string table by file offset, not by link.')
            dup = dict(name='.other', type=3, offset=STRTAB, size=3)
            save(f'link-{tag}-duplicate-offset', image(bits, endian, extra_sections=[dup]), 'string-table-link')
            # Symbol table overlapping EOF: the last records are zero-filled.
            rows = b''.join(sym(bits, endian, **r) for r in std)
            save(f'truncated-{tag}-symtab-overlaps-eof',
                 image(bits, endian, symtab=dict(offset=len(full)), symbols_at=len(full),
                       truncate=len(full) + len(rows) // 2 + 3),
                 'table-position')
            for label2, values in [('size-zero', dict(size=0)), ('size-large', dict(size=0x100000)),
                                   ('offset-past-eof', dict(offset=0x100000)), ('nobits', dict(type=8))]:
                rows = image(bits, endian)
                # Patch the .strtab record (section 4).
                record = 64 if bits == 64 else 40
                current = dict(name='.strtab', type=3, offset=STRTAB, size=len(STRINGS))
                current.update(values)
                patched = bytearray(rows)
                patched[SHOFF + record * 4:SHOFF + record * 5] = shdr(bits, endian, **current)
                save(f'strtab-{tag}-{label2}', bytes(patched), 'string-table-link')
            if bits == 64:
                record = 64
                patched = bytearray(image(bits, endian))
                patched[SHOFF + record * 4:SHOFF + record * 5] = shdr(
                    bits, endian, name='.strtab', type=3, offset=1 << 63, size=len(STRINGS))
                save(f'strtab-{tag}-negative-offset', bytes(patched), 'string-table-link')
                patched[SHOFF + record * 4:SHOFF + record * 5] = shdr(
                    bits, endian, name='.strtab', type=3, offset=STRTAB, size=1 << 63)
                save(f'strtab-{tag}-negative-size', bytes(patched), 'string-table-link')

            # Symbol names.
            def names(label2, rows, strings=STRINGS, **extra):
                save(f'name-{tag}-{label2}', image(bits, endian, rows, strings=strings, **extra), 'symbol-names')

            names('past-table', [dict(), dict(name=len(STRINGS)), dict(name=len(STRINGS) + 50)])
            names('last-byte', [dict(), dict(name=len(STRINGS) - 1)])
            names('negative', [dict(), dict(name=0xfffffff0), dict(name=0x80000000), dict(name=0xffffffff)])
            names('warning-order', [dict(name=0x900), dict(name=0x10), dict(name=0xfffffe00), dict(name=0x700),
                                    dict(name=0x10), dict(name=0x80000001)])
            names('zero-non-section', [dict(info=1), dict(info=0x12, shndx=1)])
            names('section-symbols', [dict(info=3, shndx=i) for i in (0, 1, 7, 8, 9, 100, 0xfeff, 0xff00, 0xfff1, 0xffff)])
            names('section-symbol-named', [dict(info=3, shndx=1, name=n['main'])])
            for label2, raw in [('whitespace', b'  a b \t\x01'), ('all-space', b' \t '), ('nbsp', ' x '.encode()),
                                ('surrogate', b'\xed\xa0\x80'), ('bad', b'ok\xff\xe2\x82'), ('control', b'\x7f\x1f')]:
                strings = STRINGS + raw + b'\0'
                names(f'utf8-{label2}', [dict(), dict(name=len(STRINGS), info=0x12)], strings=strings)
            # Unterminated name at EOF: string table as the file's last bytes.
            tail = image(bits, endian)
            end_strings = len(tail)
            record = 64 if bits == 64 else 40
            patched = bytearray(tail)
            patched[SHOFF + record * 4:SHOFF + record * 5] = shdr(
                bits, endian, name='.strtab', type=3, offset=end_strings, size=8)
            save(f'name-{tag}-unterminated-eof', bytes(patched) + b'\0abc\0xyz', 'symbol-names')
            symrows = b''.join(sym(bits, endian, **r) for r in [dict(), dict(name=5)])
            patched[SYMTAB:SYMTAB + len(symrows)] = symrows
            patched[SHOFF + record * 3:SHOFF + record * 4] = shdr(
                bits, endian, name='.symtab', type=2, offset=SYMTAB, size=len(symrows), link=4, entsize=size)
            save(f'name-{tag}-unterminated-eof-read', bytes(patched) + b'\0abc\0xyz', 'symbol-names')

            # Extended section indices.
            xrows = std + [dict(name=n['main'], info=0x12, shndx=0xffff), dict(info=3, shndx=0xffff)]
            entries = list(range(len(xrows)))
            for label2, payload, values in [
                    ('valid', entries, {}), ('short', entries[:3], {}), ('empty', [], {}),
                    ('link-zero', entries, dict(link=0)), ('link-other', entries, dict(link=5)),
                    ('link-out-of-range', entries, dict(link=99)), ('remainder', entries, dict(size=4 * len(entries) + 3)),
                    ('past-eof', entries, dict(offset=0x200000)), ('entsize-odd', entries, dict(entsize=8))]:
                save(f'shndx-{tag}-{label2}', image(bits, endian, xrows, shndx=(payload, values)), 'extended-index',
                     strict_note='Strict requires the linked index table inside the file.')
            second = dict(name='.symtab_shndx', type=18, offset=SHNDX + 4, size=8, link=3, entsize=4)
            save(f'shndx-{tag}-two-tables', image(bits, endian, xrows, shndx=(entries, {}), extra_sections=[second]),
                 'extended-index')
            save(f'shndx-{tag}-unlinked-only', image(bits, endian, xrows, extra_sections=[dict(second, link=5)]),
                 'extended-index')
            if bits == 64:
                for label2, values in [('negative-offset', dict(offset=1 << 63)),
                                       ('wrapping-offset', dict(offset=LONG_MAX - 7)),
                                       ('negative-size', dict(size=(1 << 64) - 8))]:
                    save(f'shndx-{tag}-{label2}', image(bits, endian, xrows, shndx=(entries, values)), 'extended-index')

            # Dynamic-table naming rule.
            save(f'dynamic-{tag}-dynsym-named-other', image(bits, endian, extra_sections=[
                dict(name='.other', type=11, offset=DYNSYM, size=entsize(bits) * 2, link=6, entsize=entsize(bits))]),
                'dynamic-name')
            save(f'dynamic-{tag}-symtab-named-dynsym', image(bits, endian, symtab=dict(name=SHNAME['.dynsym'])),
                 'dynamic-name')

            # Resource bounds, enforced by both the oracle and Rust before decoding.
            save(f'limit-{tag}-symbols', image(bits, endian, symtab=dict(entsize=1, size=1_000_001)), 'resource-bound')
            save(f'limit-{tag}-symbols-at-cap-zero-count', image(bits, endian, symtab=dict(entsize=8, size=7)),
                 'resource-bound')
            five = [dict(name=f'.t{i}', type=2, offset=SYMTAB, size=900_000, link=4, entsize=1) for i in range(5)]
            save(f'limit-{tag}-total-symbols', image(bits, endian, extra_sections=five), 'resource-bound')
            save(f'limit-{tag}-index-table', image(bits, endian, xrows, shndx=(entries, dict(size=4 * 1_000_001))),
                 'resource-bound')

            # Header and section-level recovery inherited from earlier components.
            data = bytearray(image(bits, endian))
            data[5] = 0 if endian == '<' else 3
            save(f'encoding-{tag}', data, 'encoding-compatibility')
            save(f'truncated-{tag}-section-table', image(bits, endian)[:SHOFF + 3 * (64 if bits == 64 else 40) + 7],
                 'truncation')
            save(f'prelink-trailer-{tag}', image(bits, endian) + struct.pack(endian + 'I', 0x10000000) + b'PRE ',
                 'raw-address-scope')

    # Randomized symbol tables: random st_name values, including out-of-range and
    # negative ones, random section indices and random name bytes.
    rng = random.Random(0x5717)
    alphabet = list(range(0x20, 0x7f)) * 3 + list(range(0x80, 0xc0)) + [0x09, 0xc3, 0xe2, 0xed, 0xf0, 0xff]
    for seed in range(4):
        bits, endian = ((64, '<'), (32, '>'), (64, '>'), (32, '<'))[seed]
        names_list = [bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 8))) for _ in range(150)]
        strings, offsets = strtab([b''] + names_list)
        values = list(offsets.values())
        rows = []
        for _ in range(300):
            choice = rng.random()
            if choice < 0.7:
                name = rng.choice(values) + rng.choice((0, 0, 0, 1, 2))
            elif choice < 0.85:
                name = rng.randint(0, len(strings) + 64)
            else:
                name = rng.choice((0xffffffff, 0x80000000, 0xfffffff0, rng.randint(0, 0xffffffff)))
            rows.append(dict(name=name, info=rng.randint(0, 255), other=rng.randint(0, 255),
                             shndx=rng.choice((0, 1, 2, 3, 7, 9, 0xfff1, 0xffff, rng.randint(0, 0xffff))),
                             value=rng.getrandbits(bits), size=rng.getrandbits(bits)))
        entries = [rng.getrandbits(32) for _ in range(250)]
        # Keep the symbol table clear of the string table it follows.
        save(f'random-{bits}-{seed}', image(bits, endian, rows, strings=strings,
                                           symtab=dict(offset=0x2000), symbols_at=0x2000,
                                           shndx=(entries, dict(offset=0x8000))),
             'randomized')

    cases.sort(key=lambda x: x['file'])
    manifest = dict(schema=1, resource_bounds=dict(section_headers=65536, symbols_per_table=1_000_000),
                    purpose='Original ELF string/symbol-table parser parity without a dynamic table.',
                    cases=cases, groups={group: sum(c['group'] == group for c in cases)
                                         for group in sorted({c['group'] for c in cases})})
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = generate(args.output)
    print(f"Generated {len(manifest['cases'])} immutable symbol-table fixtures at {args.output}")
