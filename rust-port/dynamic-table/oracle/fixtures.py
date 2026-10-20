"""Deterministic, bounded ELF dynamic-table fixtures; no executable payloads.

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
BASE = 0x400000
PHOFF = 0x40
DYNSYM = 0x200
DYNSTR = 0x300
HASH = 0x380
GNUHASH = 0x3c0
XHASH = 0x440
DYNAMIC = 0x500
SHSTRTAB = 0x780
SHOFF = 0x800
LOAD_END = SHOFF

DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT = 0, 1, 4, 5, 6, 10, 11
DT_DEBUG = 21
DT_GNU_XHASH, DT_GNU_HASH = 0x6ffffef4, 0x6ffffef5
PT_LOAD, PT_DYNAMIC = 1, 2

SECTION_NAMES = ['', '.dynsym', '.dynstr', '.hash', '.gnu.hash', '.dynamic', '.shstrtab', '.other',
                 '.symtab', '.strtab']


def strtab(names):
    data, offsets = bytearray(), {}
    for name in names:
        offsets[name] = len(data)
        data += (name if isinstance(name, bytes) else name.encode()) + b'\0'
    return bytes(data), offsets


SHSTR, SHNAME = strtab(SECTION_NAMES)
DYNSTRINGS, DYNNAME = strtab(['', 'libc.so.6', 'libm.so.6', 'puts', 'malloc', 'exported_fn', 'data_var',
                              ' padded.so\t'])


def entsize(bits):
    return 24 if bits == 64 else 16


def header(bits, endian, **changes):
    fields = dict(type=3, machine=62 if bits == 64 else 3, version=1, entry=0, phoff=PHOFF, shoff=SHOFF,
                  flags=0, ehsize=64 if bits == 64 else 52, phentsize=56 if bits == 64 else 32,
                  phnum=0, shentsize=64 if bits == 64 else 40, shnum=0, shstrndx=0)
    fields.update(changes)
    ident = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2, 1, 0, 0]) + bytes(7)
    return ident + struct.pack(endian + ('HHIQQQIHHHHHH' if bits == 64 else 'HHIIIIIHHHHHH'), *fields.values())


def phdr(bits, endian, type=0, flags=4, offset=0, vaddr=0, paddr=None, filesz=0, memsz=None, align=0x1000):
    paddr = vaddr if paddr is None else paddr
    memsz = filesz if memsz is None else memsz
    if bits == 64:
        return struct.pack(endian + 'IIQQQQQQ', type, flags, offset, vaddr, paddr, filesz, memsz, align)
    return struct.pack(endian + 'IIIIIIII', type, offset, vaddr, paddr, filesz, memsz, flags, align)


def shdr(bits, endian, name='', **changes):
    values = dict(name=SHNAME.get(name, 0) if isinstance(name, str) else name, type=0, flags=0, addr=0,
                  offset=0, size=0, link=0, info=0, align=0, entsize=0)
    values.update(changes)
    return struct.pack(endian + ('IIQQQQIIQQ' if bits == 64 else 'IIIIIIIIII'), *values.values())


def sym(bits, endian, name=0, info=0, other=0, shndx=0, value=0, size=0):
    if bits == 64:
        return struct.pack(endian + 'IBBHQQ', name, info, other, shndx, value, size)
    return struct.pack(endian + 'IIIBBH', name, value, size, info, other, shndx)


def dyn(bits, endian, entries):
    form = endian + ('qQ' if bits == 64 else 'iI')
    out = bytearray()
    for tag, value in entries:
        if bits == 64:
            out += struct.pack(endian + 'QQ', tag & ((1 << 64) - 1), value)
        else:
            out += struct.pack(form, tag if tag < (1 << 31) else tag - (1 << 32), value)
    return bytes(out)


def standard_symbols():
    n = DYNNAME
    return [dict(), dict(name=n['puts'], info=0x12), dict(name=n['malloc'], info=0x12),
            dict(name=n['exported_fn'], info=0x12, shndx=0xfff1, value=BASE + 0x600, size=0x10),
            dict(name=n['data_var'], info=0x11, shndx=0xfff1, value=BASE + 0x700, size=8)]


def sysv_hash(endian, nchain=5, nbucket=1):
    return struct.pack(endian + 'II', nbucket, nchain) + struct.pack(endian + 'I', 1) * nbucket + \
        struct.pack(endian + 'I' * nchain, *[0] * nchain)


def gnu_hash(bits, endian, buckets=(1, 3), symoffset=1, bloom=1, chains=(2, 5, 6, 9), shift=6):
    word = 'Q' if bits == 64 else 'I'
    return (struct.pack(endian + 'IIII', len(buckets), symoffset, bloom, shift)
            + struct.pack(endian + word * bloom, *[0xffffffff] * bloom)
            + struct.pack(endian + 'I' * len(buckets), *buckets)
            + struct.pack(endian + 'I' * len(chains), *chains))


def xhash(endian, ngnusyms=4, symndx=1):
    return struct.pack(endian + 'IIII', ngnusyms, 1, symndx, 6) + bytes(16)


def default_dynamic(bits, hash_kind='both', needed=('libc.so.6', 'libm.so.6'), strsz=None):
    entries = [(DT_NEEDED, DYNNAME[name]) for name in needed]
    if hash_kind in ('sysv', 'both'):
        entries.append((DT_HASH, BASE + HASH))
    if hash_kind in ('gnu', 'both', 'gnu+xhash'):
        entries.append((DT_GNU_HASH, BASE + GNUHASH))
    if hash_kind in ('xhash', 'gnu+xhash'):
        entries.append((DT_GNU_XHASH, BASE + XHASH))
    entries += [(DT_STRTAB, BASE + DYNSTR), (DT_SYMTAB, BASE + DYNSYM),
                (DT_STRSZ, len(DYNSTRINGS) if strsz is None else strsz), (DT_SYMENT, entsize(bits)),
                (DT_NULL, 0)]
    return entries


def replace(entries, tag, value=None, drop=False):
    out = []
    for t, v in entries:
        if t == tag:
            if drop:
                continue
            v = value
        out.append((t, v))
    return out


def image(bits, endian, dynamic=None, hash_kind='both', symbols=None, sections=True, segments=None,
          load=None, dynamic_segment=None, section_changes=None, extra_sections=(), blobs=(),
          drop_sections=(), extra_segments=(), strings=DYNSTRINGS, hashes=None, truncate=None, tail=b'',
          **header_changes):
    """Program headers: PT_LOAD over [0, SHOFF) at BASE, then PT_DYNAMIC. Sections:
    0 null, 1 .dynsym, 2 .dynstr, 3 .hash, 4 .gnu.hash, 5 .dynamic, 6 .shstrtab."""
    if dynamic is None:
        dynamic = default_dynamic(bits, hash_kind)
    if symbols is None:
        symbols = standard_symbols()
    symbol_bytes = b''.join(sym(bits, endian, **row) for row in symbols)
    dynamic_bytes = dyn(bits, endian, dynamic)
    if hashes is None:
        hashes = [(HASH, sysv_hash(endian)), (GNUHASH, gnu_hash(bits, endian)), (XHASH, xhash(endian))]
    load_values = dict(type=PT_LOAD, flags=5, offset=0, vaddr=BASE, filesz=LOAD_END)
    load_values.update(load or {})
    dyn_values = dict(type=PT_DYNAMIC, flags=6, offset=DYNAMIC, vaddr=BASE + DYNAMIC, filesz=len(dynamic_bytes),
                      align=8)
    dyn_values.update(dynamic_segment or {})
    if segments is None:
        segments = [load_values, dyn_values]
    segments = list(segments) + list(extra_segments)
    dynamic_entsize = 16 if bits == 64 else 8
    section_list = [
        dict(), dict(name='.dynsym', type=11, flags=2, addr=BASE + DYNSYM, offset=DYNSYM, size=len(symbol_bytes),
                     link=2, info=1, align=8, entsize=entsize(bits)),
        dict(name='.dynstr', type=3, flags=2, addr=BASE + DYNSTR, offset=DYNSTR, size=len(strings), align=1),
        dict(name='.hash', type=5, flags=2, addr=BASE + HASH, offset=HASH, size=0x20, link=1, align=8, entsize=4),
        dict(name='.gnu.hash', type=0x6ffffff6, flags=2, addr=BASE + GNUHASH, offset=GNUHASH, size=0x40, link=1,
             align=8),
        dict(name='.dynamic', type=6, flags=3, addr=BASE + DYNAMIC, offset=DYNAMIC, size=len(dynamic_bytes),
             link=2, align=8, entsize=dynamic_entsize),
        dict(name='.shstrtab', type=3, offset=SHSTRTAB, size=len(SHSTR), align=1)]
    for name, changes in (section_changes or {}).items():
        for values in section_list:
            if values.get('name') == name:
                values.update(changes)
    section_list = [s for s in section_list if s.get('name') not in drop_sections] + list(extra_sections)
    if not sections:
        section_list = []
    shstrndx = next((i for i, s in enumerate(section_list) if s.get('name') == '.shstrtab'), 0)
    record = 64 if bits == 64 else 40
    phentsize = 56 if bits == 64 else 32
    head = dict(phnum=len(segments), shnum=len(section_list), shstrndx=shstrndx,
                shoff=SHOFF if section_list else 0)
    head.update(header_changes)
    data = bytearray(header(bits, endian, **head))
    end = SHOFF + record * len(section_list) if section_list else LOAD_END
    data.extend(bytes(end - len(data)))
    for i, values in enumerate(segments):
        data[PHOFF + phentsize * i:PHOFF + phentsize * (i + 1)] = phdr(bits, endian, **values)
    for offset, blob in [(SHSTRTAB, SHSTR), (DYNSTR, strings), (DYNSYM, symbol_bytes), (DYNAMIC, dynamic_bytes),
                         *hashes, *blobs]:
        if len(data) < offset + len(blob):
            data.extend(bytes(offset + len(blob) - len(data)))
        data[offset:offset + len(blob)] = blob
    for i, values in enumerate(section_list):
        data[SHOFF + record * i:SHOFF + record * (i + 1)] = shdr(bits, endian, **values)
    data = bytes(data[:truncate] if truncate is not None else data)
    return data + tail


def generate(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    cases = []

    def save(name, data, group, expected_difference=None, strict_note=None):
        name += '.elf'
        if any(case['file'] == name for case in cases):
            raise ValueError(f'duplicate fixture {name}')
        (output / name).write_bytes(data)
        cases.append(dict(file=name, group=group, length=len(data), sha256=hashlib.sha256(data).hexdigest(),
                          expected_difference=expected_difference, strict_note=strict_note))

    for bits in (32, 64):
        for endian, label in (('<', 'le'), ('>', 'be')):
            tag = f'{bits}-{label}'
            es = entsize(bits)
            full = default_dynamic(bits)
            ns = dict(sections=False)

            def case(name, group, **kw):
                save(f'{name}-{tag}', image(bits, endian, **kw), group)

            # Canonical shared objects, with and without section headers.
            case('canonical', 'canonical')
            for kind in ('sysv', 'gnu', 'xhash', 'both', 'gnu+xhash'):
                case(f'canonical-no-sections-{kind.replace("+", "-")}', 'canonical', hash_kind=kind, **ns)
            case('canonical-no-needed', 'canonical', dynamic=default_dynamic(bits, needed=()))
            case('canonical-no-dynamic', 'canonical', segments=[dict(type=PT_LOAD, offset=0, vaddr=BASE,
                                                                       filesz=LOAD_END)], drop_sections=('.dynamic',))
            case('canonical-no-segments', 'canonical', segments=[], phoff=0)
            case('canonical-many-needed', 'canonical',
                 dynamic=[(DT_NEEDED, DYNNAME['libc.so.6'])] * 30 + full)

            # Locating the table.
            case('dynamic-stripped-vaddr', 'dynamic-location', dynamic_segment=dict(vaddr=0))
            case('dynamic-stripped-filesz', 'dynamic-location', dynamic_segment=dict(filesz=0))
            case('dynamic-stripped-no-sections', 'dynamic-location', dynamic_segment=dict(vaddr=0), **ns)
            second = dict(type=PT_DYNAMIC, offset=DYNAMIC, vaddr=BASE + DYNAMIC, filesz=0x40)
            case('dynamic-two-segments', 'dynamic-location', extra_segments=[second])
            case('dynamic-two-segments-no-sections', 'dynamic-location', extra_segments=[second], **ns)
            case('dynamic-two-segments-section-unloaded', 'dynamic-location', extra_segments=[second],
                 section_changes={'.dynamic': dict(addr=0x900000)})
            case('dynamic-not-in-load', 'dynamic-location', dynamic_segment=dict(vaddr=0x900000))
            case('dynamic-not-in-load-bad-offset', 'dynamic-location',
                 dynamic_segment=dict(vaddr=0x900000, offset=0x7000))
            case('dynamic-wrong-offset', 'dynamic-location', dynamic_segment=dict(offset=0x10))
            case('dynamic-load-offset', 'dynamic-location', load=dict(offset=0x100, vaddr=BASE + 0x100,
                                                                       filesz=LOAD_END - 0x100))
            case('dynamic-past-eof', 'dynamic-location', dynamic_segment=dict(vaddr=BASE + 0x10000),
                 load=dict(memsz=0x20000))
            case('dynamic-section-only', 'dynamic-location', segments=[dict(type=PT_LOAD, offset=0, vaddr=BASE,
                                                                             filesz=LOAD_END)])
            case('dynamic-section-only-unloaded', 'dynamic-location',
                 segments=[dict(type=PT_LOAD, offset=0, vaddr=BASE, filesz=LOAD_END)],
                 section_changes={'.dynamic': dict(addr=0x900000)})
            case('dynamic-two-sections', 'dynamic-location',
                 segments=[dict(type=PT_LOAD, offset=0, vaddr=BASE, filesz=LOAD_END)],
                 extra_sections=[dict(name='.other', type=6, addr=BASE + DYNAMIC, offset=DYNAMIC, size=0x40)])
            case('dynamic-segment-and-other-section', 'dynamic-location',
                 section_changes={'.dynamic': dict(addr=BASE + 0x10, offset=0x10)})
            case('dynamic-unterminated', 'dynamic-location', dynamic=full[:-1],
                 dynamic_segment=dict(vaddr=BASE + LOAD_END - 16 * 2), blobs=[(LOAD_END - 32, dyn(bits, endian, [
                     (DT_DEBUG, 1), (DT_DEBUG, 2)]))], **ns)
            if bits == 64:
                case('dynamic-negative-offset', 'dynamic-location', load=dict(offset=1 << 63, vaddr=BASE))
                case('dynamic-near-long-max', 'dynamic-location',
                     load=dict(offset=LONG_MAX - DYNAMIC - 4, vaddr=BASE))
                case('dynamic-tag-truncated-null', 'dynamic-entries',
                     dynamic=[(DT_NEEDED, 1), (1 << 32, 7)] + full)
                case('dynamic-tag-truncated-strtab', 'dynamic-entries',
                     dynamic=[((1 << 32) | DT_STRTAB, BASE + DYNSTR)] + replace(full, DT_STRTAB, drop=True), **ns)
            case('dynamic-high-tags', 'dynamic-entries',
                 dynamic=[(0x7fffffff, 1), (0x80000000, 2), (0xffffffff, 3), (DT_DEBUG, 0)] + full)
            case('dynamic-duplicate-strtab', 'dynamic-entries',
                 dynamic=[(DT_STRTAB, BASE + DYNSTR + 1)] + full, **ns)

            # The dynamic string table.
            case('strtab-missing', 'string-table', dynamic=replace(full, DT_STRTAB, drop=True))
            case('strtab-missing-no-sections', 'string-table', dynamic=replace(full, DT_STRTAB, drop=True), **ns)
            case('strtab-missing-strsz', 'string-table', dynamic=replace(full, DT_STRSZ, drop=True), **ns)
            case('strtab-missing-strsz-sections', 'string-table', dynamic=replace(full, DT_STRSZ, drop=True))
            case('strtab-zero', 'string-table', dynamic=replace(full, DT_STRTAB, 0), **ns)
            case('strtab-unloaded', 'string-table', dynamic=replace(full, DT_STRTAB, 0x900000), **ns)
            case('strtab-in-bss', 'string-table', dynamic=replace(full, DT_STRTAB, 0x500010),
                 extra_segments=[dict(type=PT_LOAD, offset=0x2000, vaddr=0x500000, filesz=0, memsz=0x1000)], **ns)
            case('strtab-section-address-differs', 'string-table',
                 section_changes={'.dynstr': dict(addr=BASE + 0x10)})
            case('strtab-section-elsewhere', 'string-table',
                 section_changes={'.dynstr': dict(offset=0x10, addr=BASE + DYNSTR)})
            case('strtab-size-large', 'string-table', dynamic=replace(full, DT_STRSZ, 0x100000), **ns)
            if bits == 64:
                case('strtab-size-negative', 'string-table', dynamic=replace(full, DT_STRSZ, 1 << 63), **ns)
                case('strtab-address-minus-one', 'string-table', dynamic=replace(full, DT_STRTAB, (1 << 64) - 1),
                     **ns)
                case('strtab-section-address-minus-one', 'string-table', segments=[], phoff=0,
                     section_changes={'.dynstr': dict(addr=(1 << 64) - 1)})
                case('symtab-section-address-minus-one', 'symbol-table', segments=[], phoff=0,
                     section_changes={'.dynsym': dict(addr=(1 << 64) - 1)})
            case('prelink', 'prelink', tail=struct.pack(endian + 'I', 0x10000000) + b'PRE ')
            case('prelink-no-sections', 'prelink', tail=struct.pack(endian + 'I', 0x10000000) + b'PRE ', **ns)
            case('prelink-variant', 'prelink', tail=struct.pack(endian + 'I', 0x1000) + b'\x01PRE', **ns)
            case('prelink-not-magic', 'prelink', tail=struct.pack(endian + 'I', 0x1000) + b'PREX', **ns)

            # DT_NEEDED names.
            def needed(name, values, **kw):
                case(f'needed-{name}', 'library-names',
                     dynamic=[(DT_NEEDED, value) for value in values] + replace(full, DT_NEEDED, drop=True), **kw)

            needed('past-table', [len(DYNSTRINGS), len(DYNSTRINGS) + 40, 0x7fffffff], **ns)
            needed('last-byte', [len(DYNSTRINGS) - 1], **ns)
            needed('padded', [DYNNAME[' padded.so\t'], 0], **ns)
            if bits == 64:
                needed('negative', [1 << 63, (1 << 64) - 1], **ns)
            case('needed-no-string-table', 'library-names',
                 dynamic=replace([(DT_NEEDED, 1)] + full, DT_STRTAB, drop=True), **ns)
            for label2, raw in [('surrogate', b'\xed\xa0\x80'), ('bad', b'ok\xff\xe2\x82'), ('space', b' \t ')]:
                strings = DYNSTRINGS + raw + b'\0'
                case(f'needed-utf8-{label2}', 'library-names', strings=strings,
                     dynamic=[(DT_NEEDED, len(DYNSTRINGS))] + replace(full, DT_STRSZ, len(strings)), **ns)
            unterminated = image(bits, endian, **ns)
            strings_at = len(unterminated)
            data = image(bits, endian, dynamic=[(DT_NEEDED, 1)] + replace(replace(
                full, DT_STRTAB, BASE + strings_at), DT_STRSZ, 8), load=dict(filesz=strings_at + 0x10), **ns)
            save(f'needed-unterminated-eof-{tag}', data + b'\0libz', 'library-names')

            # The dynamic symbol table.
            def symtab(name, entries, **kw):
                case(f'symtab-{name}', 'symbol-table', dynamic=entries, **kw)

            symtab('missing', replace(full, DT_SYMTAB, drop=True), **ns)
            symtab('missing-sections', replace(full, DT_SYMTAB, drop=True))
            symtab('missing-syment', replace(full, DT_SYMENT, drop=True), **ns)
            symtab('missing-hash', replace(replace(full, DT_HASH, drop=True), DT_GNU_HASH, drop=True), **ns)
            symtab('missing-syment-no-strtab', replace(replace(full, DT_SYMENT, drop=True), DT_STRTAB, drop=True),
                   **ns)
            symtab('zero', replace(full, DT_SYMTAB, 0), **ns)
            symtab('zero-no-strtab', replace(replace(full, DT_SYMTAB, 0), DT_STRTAB, drop=True), **ns)
            symtab('no-strtab', replace(full, DT_STRTAB, drop=True), **ns)
            symtab('unloaded', replace(full, DT_SYMTAB, 0x900000), **ns)
            symtab('hash-unloaded', replace(full, DT_HASH, 0x900000), **ns)
            symtab('in-bss', replace(full, DT_SYMTAB, 0x500010),
                   extra_segments=[dict(type=PT_LOAD, offset=0x2000, vaddr=0x500000, filesz=0, memsz=0x1000)], **ns)
            for value in (0, 1, es - 1, es + 8, 0x100):
                symtab(f'syment-{value:x}', replace(full, DT_SYMENT, value), **ns)
            if bits == 64:
                symtab('syment-wrapping', replace(full, DT_SYMENT, 1 << 62), **ns)
                symtab('syment-negative', replace(full, DT_SYMENT, (1 << 64) - 24), **ns)
            symtab('section-address-differs', full, section_changes={'.dynsym': dict(addr=BASE + 0x10)})
            symtab('section-invalid-offset', full,
                   section_changes={'.dynsym': dict(offset=(1 << bits) - 1)})
            symtab('section-is-symtab', full, section_changes={'.dynsym': dict(type=2)})
            symtab('past-eof', replace(full, DT_SYMTAB, BASE + LOAD_END - es * 2),
                   load=dict(memsz=0x10000), **ns)
            symtab('names-out-of-range', full, symbols=standard_symbols() + [dict(name=0x1000), dict(name=0xffffffff)],
                   hashes=[(HASH, sysv_hash(endian, nchain=7))], **ns)

            # Hash-table symbol counts.
            def hashed(name, kind, blob, at, **kw):
                case(f'hash-{name}', 'hash-table', hash_kind=kind, hashes=[(at, blob)], **kw)

            for count in (0, 1, 3, 0x80000000, 0xffffffff):
                hashed(f'sysv-nchain-{count:x}', 'sysv', sysv_hash(endian, nchain=count if count < 8 else 0)[:4]
                       + struct.pack(endian + 'I', count), HASH, **ns)
            hashed('sysv-nchain-past-table', 'sysv', sysv_hash(endian, nchain=40), HASH, **ns)
            moved = {'.dynsym': dict(addr=BASE + 0x10)}
            hashed('gnu-valid', 'gnu', gnu_hash(bits, endian), GNUHASH, section_changes=moved)
            hashed('gnu-valid-no-sections', 'gnu', gnu_hash(bits, endian), GNUHASH, **ns)
            hashed('gnu-no-buckets', 'gnu', gnu_hash(bits, endian, buckets=()), GNUHASH, **ns)
            hashed('gnu-empty-buckets', 'gnu', gnu_hash(bits, endian, buckets=(0, 0), chains=(1,)), GNUHASH, **ns)
            hashed('gnu-symoffset-high', 'gnu', gnu_hash(bits, endian, symoffset=9), GNUHASH, **ns)
            hashed('gnu-bucket-max', 'gnu', gnu_hash(bits, endian, buckets=(0x7fffffff,)), GNUHASH, **ns)
            hashed('gnu-bucket-negative', 'gnu', gnu_hash(bits, endian, buckets=(0x80000000, 2)), GNUHASH, **ns)
            hashed('gnu-bloom-huge', 'gnu', gnu_hash(bits, endian, bloom=1)[:8] + struct.pack(endian + 'I', 0x10000000)
                   + gnu_hash(bits, endian)[12:], GNUHASH, **ns)
            hashed('gnu-bloom-wrapping', 'gnu', gnu_hash(bits, endian, bloom=1)[:8] + struct.pack(endian + 'I', 0xffffffff)
                   + gnu_hash(bits, endian)[12:], GNUHASH, **ns)
            hashed('gnu-chain-unterminated', 'gnu', gnu_hash(bits, endian, chains=(2, 4)), GNUHASH,
                   blobs=[(GNUHASH + 0x30, bytes(0x40))], **ns)
            hashed('gnu-many-buckets', 'gnu', gnu_hash(bits, endian, buckets=tuple(range(1, 40)),
                                                        chains=tuple([2] * 40 + [3])), GNUHASH, **ns)
            hashed('gnu-section-region', 'gnu', gnu_hash(bits, endian), GNUHASH,
                   section_changes={**moved, '.gnu.hash': dict(size=0x18)})
            hashed('gnu-region-past-eof', 'gnu', gnu_hash(bits, endian), GNUHASH,
                   section_changes={**moved, '.gnu.hash': dict(size=0x10000000)})
            hashed('gnu-load-region-past-eof', 'gnu', gnu_hash(bits, endian), GNUHASH,
                   load=dict(filesz=0x10000000), **ns)
            hashed('gnu-no-file-region', 'gnu', gnu_hash(bits, endian), GNUHASH,
                   dynamic=replace(default_dynamic(bits, 'gnu'), DT_GNU_HASH, 0x500010),
                   extra_segments=[dict(type=PT_LOAD, offset=0x10000, vaddr=0x500000, filesz=0x10, memsz=0x1000)],
                   **ns)
            hashed('xhash-valid', 'xhash', xhash(endian), XHASH, **ns)
            hashed('xhash-negative', 'xhash', xhash(endian, ngnusyms=0x80000000), XHASH, **ns)
            hashed('xhash-zero', 'xhash', xhash(endian, ngnusyms=0, symndx=0), XHASH, **ns)
            hashed('xhash-wrapping', 'xhash', xhash(endian, ngnusyms=0xffffffff, symndx=6), XHASH, **ns)
            if bits == 64:
                case('hash-negative-offset', 'hash-table', hash_kind='sysv',
                     dynamic=replace(default_dynamic(bits, 'sysv'), DT_HASH, 0x500000),
                     extra_segments=[dict(type=PT_LOAD, offset=1 << 63, vaddr=0x500000, filesz=0x10)], **ns)
                case('hash-gnu-negative-offset', 'hash-table', hash_kind='gnu',
                     dynamic=replace(default_dynamic(bits, 'gnu'), DT_GNU_HASH, 0x500000),
                     extra_segments=[dict(type=PT_LOAD, offset=1 << 63, vaddr=0x500000, filesz=0x10)], **ns)

            # Resource bounds, enforced by both the oracle and Rust.
            hashed('limit-symbols', 'sysv', sysv_hash(endian, nchain=1)[:4] + struct.pack(endian + 'I', 1_000_001),
                   HASH, **ns)
            four = [dict(name='.other', type=2, offset=DYNSYM, size=900_000, link=2, entsize=1) for _ in range(4)]
            hashed('limit-total', 'sysv', sysv_hash(endian, nchain=1)[:4] + struct.pack(endian + 'I', 500_000),
                   HASH, extra_sections=four, section_changes=moved)
            case('limit-dynamic-entries', 'resource-bound', dynamic=[(DT_DEBUG, 0)] * 65536 + [(DT_NULL, 0)],
                 load=dict(filesz=0x200000), **ns)
            case('limit-dynamic-entries-at-cap', 'resource-bound', dynamic=[(DT_DEBUG, 0)] * 65535 + [(DT_NULL, 0)],
                 load=dict(filesz=0x200000), **ns)

            # Header and table recovery inherited from earlier components.
            data = bytearray(image(bits, endian))
            data[5] = 0 if endian == '<' else 3
            save(f'encoding-{tag}', bytes(data), 'header')
            save(f'truncated-program-headers-{tag}', image(bits, endian, **ns)[:PHOFF + 20], 'header')
            save(f'truncated-section-table-{tag}', image(bits, endian)[:SHOFF + 3 * (64 if bits == 64 else 40)],
                 'header')
            case('limit-program-headers', 'resource-bound', phnum=4097, **ns)

    # Randomized dynamic tables over the section-less image.
    rng = random.Random(0xd1a)
    tags = [DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT, DT_GNU_HASH, DT_GNU_XHASH, DT_DEBUG, 3, 12]
    for seed in range(12):
        bits, endian = ((64, '<'), (32, '>'), (64, '>'), (32, '<'))[seed % 4]
        entries = default_dynamic(bits, rng.choice(('sysv', 'gnu', 'xhash', 'both')))[:-1]
        for _ in range(rng.randint(0, 6)):
            tag = rng.choice(tags)
            choice = rng.random()
            if choice < 0.4:
                value = BASE + rng.randrange(0, LOAD_END)
            elif choice < 0.7:
                value = rng.randrange(0, 0x60)
            else:
                value = rng.getrandbits(bits)
            entries.insert(rng.randint(0, len(entries)), (tag, value))
        if rng.random() < 0.3:
            entries = [e for e in entries if e[0] != rng.choice(tags)]
        entries.append((DT_NULL, 0))
        hashes = [(HASH, struct.pack(endian + 'II', rng.randint(0, 3), rng.choice((0, 1, 5, 8, rng.getrandbits(32))))),
                  (GNUHASH, gnu_hash(bits, endian, buckets=tuple(rng.randint(0, 8) for _ in range(rng.randint(0, 4))),
                                     symoffset=rng.randint(0, 3), bloom=rng.randint(0, 2),
                                     chains=tuple(rng.getrandbits(32) for _ in range(6)))),
                  (XHASH, xhash(endian, ngnusyms=rng.randint(0, 9), symndx=rng.randint(0, 3)))]
        rows = [dict(name=rng.randrange(0, len(DYNSTRINGS) + 8), info=rng.randint(0, 255),
                     shndx=rng.choice((0, 1, 5, 0xfff1, 0xffff)), value=rng.getrandbits(bits)) for _ in range(8)]
        save(f'random-{bits}-{seed}', image(bits, endian, dynamic=entries, hashes=hashes, symbols=rows,
                                            sections=rng.random() < 0.4), 'randomized')

    cases.sort(key=lambda x: x['file'])
    manifest = dict(schema=1, resource_bounds=dict(program_headers=4096, section_headers=65536,
                                                   dynamic_entries=65536, symbols_per_table=1_000_000,
                                                   total_symbols=4_000_000),
                    purpose='Original ELF dynamic-table, string-table, library-name and symbol-table parity.',
                    cases=cases, groups={group: sum(c['group'] == group for c in cases)
                                         for group in sorted({c['group'] for c in cases})})
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = generate(args.output)
    print(f"Generated {len(manifest['cases'])} immutable dynamic-table fixtures at {args.output}")
