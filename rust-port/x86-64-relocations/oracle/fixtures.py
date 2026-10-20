"""Deterministic ELF64 x86-64 fixtures for the relocation-handler comparison.

Each fixture is a small ET_DYN image: a read/execute PT_LOAD with symbol and
string tables and some code, a read/write PT_LOAD with patterned data and a
zero-filled tail, and relocation sections (or a dynamic table) chosen per case.
No fixture is executable code meant to run; the instruction bytes only feed
the GOTPCRELX relaxation checks.
"""
from pathlib import Path
import hashlib
import json
import random
import struct

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_NOBITS, SHT_REL, SHT_DYNSYM, SHT_RELR = 1, 2, 3, 4, 8, 9, 11, 19
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4
PT_LOAD, PT_DYNAMIC = 1, 2
DT_NULL, DT_PLTGOT, DT_RELA, DT_RELASZ, DT_RELAENT = 0, 3, 7, 8, 9
DT_GNU_PRELINKED = 0x6ffffdf5
TEXT, DATA, DATA_END, BSS_END = 0x800, 0x1000, 0x2000, 0x3000
DYNSYM, DYNSTR, DYNAMIC = 0x200, 0x600, 0x1800
SEC_TEXT, SEC_DATA = 3, 4
TYPES = list(range(0, 52)) + [250, 251]
EXTRA_TYPES = [52, 99, 249, 252, 0xffffffff]
GOT = '_GLOBAL_OFFSET_TABLE_'

# Instruction bytes in .text: (offset of the 32-bit field, bytes starting two before it).
CODE = [
    (0x902, b'\x8b\x05'),          # mov reg, [rip+x]  -> lea
    (0x912, b'\xff\x25'),          # jmp [rip+x]       -> jmp x; nop
    (0x922, b'\xff\x15'),          # call [rip+x]      -> addr32 call x
    (0x932, b'\xff\x35'),          # push [rip+x]      -> not relaxed
    (0x942, b'\x01\x05'),          # add [rip+x], reg  -> not relaxed
    (0x952, b'\x48\x8b'),          # bytes of a REX mov seen at the wrong offset
]


def symbols(got='undef'):
    """(name, info, shndx, value, size); index 0 is the null symbol."""
    rows = [
        ('', 0, 0, 0, 0),
        ('data_obj', 0x11, SEC_DATA, 0x1100, 16),
        ('func', 0x12, SEC_TEXT, TEXT, 32),
        ('ext_func', 0x12, 0, 0, 0),
        ('ext_data', 0x11, 0, 0, 0),
        ('tls_var', 0x16, SEC_DATA, 0x10, 8),
        ('', 0x03, SEC_DATA, DATA, 0),
        ('abs_sym', 0x10, 0xfff1, 0x12345678, 4),
        ('common_sym', 0x11, 0xfff2, 8, 8),
        ('ifunc', 0x1a, SEC_TEXT, TEXT + 0x20, 16),
        ('bad name\x01\x7f', 0x11, SEC_DATA, 0x1180, 8),
        ('', 0x10, 0, 0, 0),
        ('weak_ext', 0x22, 0, 0, 0),
        ('big', 0x11, SEC_DATA, 0x1fff_ffff_ffff_fff0, -2 & (2**64 - 1)),
    ]
    if got == 'undef':
        rows.append((GOT, 0x10, 0, 0, 0))
    elif got == 'def0':
        rows.append((GOT, 0x11, SEC_DATA, 0, 0))
    elif got == 'defined':
        rows.append((GOT, 0x11, SEC_DATA, 0x1f00, 0))
    return rows


def strtab(names):
    data, offsets = bytearray(b'\0'), {'': 0}
    for name in names:
        if name not in offsets:
            offsets[name] = len(data)
            data += name.encode() + b'\0'
    return bytes(data), offsets


def info(symbol, type_id):
    return ((symbol & 0xffffffff) << 32) | (type_id & 0xffffffff)


def build(tables=(), got='undef', dynamic=None, sections=True, adjust_segments=None,
          trailer=None, machine=62, elf_class=2, elf_type=3, extra_load=None, relocated_debug=False,
          patch=None):
    """tables: (kind, rows, link, info) with kind 'rela', 'rel' or 'relr' and
    rows (offset, info, addend) or RELR words."""
    syms = symbols(got)
    dynstr, names = strtab([row[0] for row in syms])
    image = bytearray(BSS_END)
    for i in range(DATA, DATA_END):
        image[i] = (i * 37 + 11) & 0xff
    for field, opcode in CODE:
        image[field - 2:field] = opcode
        image[field:field + 4] = b'\xf8\xff\xff\xff'
    for i, (name, sinfo, shndx, value, size) in enumerate(syms):
        image[DYNSYM + 24 * i:DYNSYM + 24 * (i + 1)] = struct.pack('<IBBHQQ', names[name], sinfo, 0, shndx, value, size)
    image[DYNSTR:DYNSTR + len(dynstr)] = dynstr
    if dynamic is not None:
        blob = b''.join(struct.pack('<qQ', tag, value) for tag, value in dynamic + [(DT_NULL, 0)])
        image[DYNAMIC:DYNAMIC + len(blob)] = blob
    for at, value in (patch or {}).items():
        image[at:at + len(value)] = value
    image = image[:DATA_END]

    segments = [(PT_LOAD, 5, 0, 0, DATA, DATA), (PT_LOAD, 6, DATA, DATA, DATA_END - DATA, BSS_END - DATA)]
    if dynamic is not None:
        segments.append((PT_DYNAMIC, 6, DYNAMIC, DYNAMIC, 0x200, 0x200))
    if extra_load:
        segments.append(extra_load)
    if adjust_segments:
        segments = adjust_segments(segments)

    section_list = [('', 0, 0, 0, 0, 0, 0, 0, 0, 0),
                    ('.dynsym', SHT_DYNSYM, SHF_ALLOC, DYNSYM, DYNSYM, 24 * len(syms), 2, 1, 8, 24),
                    ('.dynstr', SHT_STRTAB, SHF_ALLOC, DYNSTR, DYNSTR, len(dynstr), 0, 0, 1, 0),
                    ('.text', SHT_PROGBITS, SHF_ALLOC | SHF_EXEC, TEXT, TEXT, DATA - TEXT, 0, 0, 16, 0),
                    ('.data', SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, DATA, DATA, DATA_END - DATA, 0, 0, 16, 0),
                    ('.bss', SHT_NOBITS, SHF_ALLOC | SHF_WRITE, DATA_END, DATA_END, BSS_END - DATA_END, 0, 0, 16, 0)]
    debug_index = None
    if relocated_debug:
        debug_index = len(section_list)
        section_list.append(('.debug_info', SHT_PROGBITS, 0, 0, 0x100, 0x40, 0, 0, 1, 0))
    for kind, rows, link, info_index in tables:
        if kind == 'relr':
            blob = b''.join(struct.pack('<Q', word) for word in rows)
            stype, entsize, name = SHT_RELR, 8, '.relr.dyn'
        elif kind == 'rela':
            blob = b''.join(struct.pack('<QQq', o, i, a) for o, i, a in rows)
            stype, entsize, name = SHT_RELA, 24, '.rela.dyn'
        else:
            blob = b''.join(struct.pack('<QQ', o, i) for o, i, _ in rows)
            stype, entsize, name = SHT_REL, 16, '.rel.dyn'
        if info_index == 'debug':
            info_index, name = debug_index, '.rela.debug_info'
        offset = len(image)
        image += blob
        section_list.append((name, stype, 0, 0, offset, len(blob), link, info_index, 8, entsize))
    shnames = [row[0] for row in section_list] + ['.shstrtab']
    shstr, shoff_names = strtab(shnames)
    shstr_offset = len(image)
    image += shstr
    section_list.append(('.shstrtab', SHT_STRTAB, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0))
    while len(image) % 8:
        image += b'\0'
    shoff = len(image)
    if sections:
        for name, stype, flags, addr, offset, size, link, sinfo, align, entsize in section_list:
            image += struct.pack('<IIQQQQIIQQ', shoff_names[name], stype, flags, addr, offset, size,
                                 link, sinfo, align, entsize)
    phdrs = b''.join(struct.pack('<IIQQQQQQ', t, f, o, v, v, fs, ms, 0x1000) for t, f, o, v, fs, ms in segments)
    image[0x40:0x40 + len(phdrs)] = phdrs
    header = (b'\x7fELF' + bytes([elf_class, 1, 1, 0]) + bytes(8)
              + struct.pack('<HHIQQQIHHHHHH', elf_type, machine, 1, 0, 0x40, shoff if sections else 0, 0, 64, 56,
                            len(segments), 64, len(section_list) if sections else 0,
                            len(section_list) - 1 if sections else 0))
    image[:64] = header
    if trailer:
        image += trailer
    return bytes(image)


def sweep_rows(symbol, addend, types=TYPES + EXTRA_TYPES, base=0x1100):
    return [(base + 16 * k, info(symbol, t), addend) for k, t in enumerate(types)]


def relaxation_rows(symbol, addend=-4):
    rows = []
    for type_id in (41, 42, 9):
        for field, _ in CODE:
            rows.append((field, info(symbol, type_id), addend))
    return rows


def cases():
    out = []

    def add(name, group, data, adjust=0x100000, unresolved=False, note=''):
        out.append(dict(name=name, group=group, data=data, adjust=adjust, unresolved=unresolved, note=note))

    syms = symbols()
    # Every type id, for every kind of symbol and three addends.
    for index in list(range(len(syms))) + [99, -1]:
        for addend in (0, -4, 0x10):
            rows = sweep_rows(index, addend)
            add(f'sweep-sym{index}-add{addend}', 'type-sweep', build([('rela', rows, 1, 0)]),
                note='RELA record of every type id')
    add('sweep-unresolved', 'type-sweep', build([('rela', sweep_rows(3, 8), 1, 0)]), unresolved=True)
    add('sweep-rel-implicit', 'type-sweep', build([('rel', sweep_rows(1, 0), 1, 0)]),
        note='REL records: addends read from memory')
    add('sweep-adjust0', 'type-sweep', build([('rela', sweep_rows(1, 0x20), 1, 0)]), adjust=0)
    # GOT handling: no GOT symbol, an undefined one, one defined at 0 or elsewhere, DT_PLTGOT.
    for got in ('none', 'undef', 'def0', 'defined'):
        for adjust in (0x100000, 0):
            rows = sweep_rows(1, 0x10) + sweep_rows(len(symbols(got)) - 1, 0, base=0x1500)
            add(f'got-{got}-adjust{adjust:x}', 'got', build([('rela', rows, 1, 0)], got=got), adjust=adjust)
    add('got-pltgot', 'got', build([('rela', sweep_rows(1, 0x10), 1, 0)], got='none',
                                   dynamic=[(DT_PLTGOT, 0x1f80)]))
    add('got-high-adjust', 'got', build([('rela', sweep_rows(2, 0), 1, 0)]), adjust=0x8000000000000000,
        note='signed check of the %got address passes for addresses past 2^63')
    add('got-over-int-max', 'got', build([('rela', sweep_rows(2, 0), 1, 0)]), adjust=0x7fffd000,
        note='the %got block would start at 0x80000000, past Integer.MAX_VALUE')
    add('got-no-room', 'got', build([('rela', sweep_rows(2, 0), 1, 0)]), adjust=(1 << 64) - BSS_END,
        unresolved=True, note='no linkage block fits above the image')
    many = [(0x1100 + 8 * k, info(s, 9), 0) for k, s in enumerate([1, 2, 7, 9, 10, 13, 1, 2, 3, 4, 12])]
    add('got-many-entries', 'got', build([('rela', many, 1, 0)]))
    # GOTPCRELX relaxation of each instruction form, per symbol kind.
    for index in (2, 1, 3, 9, 0, 7):
        add(f'relax-sym{index}', 'relaxation', build([('rela', relaxation_rows(index), 1, 0)]))
    add('relax-unresolved', 'relaxation', build([('rela', relaxation_rows(3), 1, 0)]), unresolved=True)
    add('relax-segment-start', 'relaxation', build([('rela', [(0, info(2, 41), 0), (1, info(2, 42), 0)], 1, 0)]),
        note='op bytes below the first block: a memory failure')
    add('relax-address-zero', 'relaxation', build([('rela', [(0, info(2, 41), 0)], 1, 0)]), adjust=0,
        note='Address.subtract underflow: the run aborts')
    def no_bss(segments):
        return [(t, f, o, v, fs, fs if v == DATA else ms) for t, f, o, v, fs, ms in segments]
    top_jmp = build([('rela', [(DATA_END - 3, info(2, 41), 0)], 1, 0)], adjust_segments=no_bss,
                    patch={DATA_END - 5: b'\xff\x25'})
    add('relax-jmp-top', 'relaxation', top_jmp, adjust=(1 << 64) - DATA_END, unresolved=True,
        note='the appended NOP would lie past the top of the address space: the run aborts')
    # RELR, REL and table-level cases.
    relr = [DATA + 0x100, (0b1011 << 1) | 1, DATA + 0x400, (1 << 63) | 1]
    add('relr', 'tables', build([('relr', relr, 0, 0)]))
    add('relr-adjust0', 'tables', build([('relr', relr, 0, 0)]), adjust=0)
    add('relr-prelink', 'tables', build([('relr', relr, 0, 0)], trailer=struct.pack('<I', 0x40000) + b'PRE\0'))
    add('prelink-trailer', 'tables', build([('rela', sweep_rows(1, 4), 1, 0)],
                                           trailer=struct.pack('<I', 0x40000) + b'PRE\0'))
    add('prelink-dynamic', 'tables', build([('rela', sweep_rows(1, 4), 1, 0)],
                                           dynamic=[(DT_GNU_PRELINKED, 1)]))
    add('relocated-text', 'tables', build([('rela', sweep_rows(2, 1), 1, SEC_TEXT)]))
    add('relocated-debug', 'tables', build([('rela', sweep_rows(2, 1), 1, 'debug')], relocated_debug=True),
        note='relocations of a non-allocated section are skipped')
    unmapped = [(BSS_END + 0x10, info(1, 1), 0), (BSS_END - 4, info(1, 1), 0), (BSS_END - 4, info(1, 2), 0),
                (BSS_END - 1, info(1, 14), 0), (BSS_END - 1, info(1, 12), 0), (0x5000, info(1, 0), 0),
                (BSS_END - 8, info(1, 8), 0), (0x1ffffffff, info(0, 8), 1)]
    add('unmapped', 'tables', build([('rela', unmapped, 1, 0), ('rel', unmapped, 1, 0)]))
    rela_table = struct.pack('<QQq', 0x1100, info(1, 1), 0) + struct.pack('<QQq', 0x1108, info(0, 8), 5)
    image = bytearray(build(dynamic=[(DT_RELA, 0x1a00), (DT_RELASZ, len(rela_table)), (DT_RELAENT, 24)],
                            sections=False))
    image[0x1a00:0x1a00 + len(rela_table)] = rela_table
    add('dynamic-no-symtab', 'tables', bytes(image), note='a DT_RELA table with no symbol table')
    add('two-tables', 'tables', build([('rela', sweep_rows(1, 0), 1, 0), ('rela', sweep_rows(3, 0), 1, 0)]))
    # Inputs the model does not run.
    add('reject-elf32', 'rejected', build(elf_class=1))
    add('reject-machine', 'rejected', build([('rela', sweep_rows(1, 0), 1, 0)], machine=3))
    add('reject-relocatable', 'rejected', build([('rela', sweep_rows(1, 0), 1, 0)], elf_type=1))
    add('reject-overlap', 'rejected', build(extra_load=(PT_LOAD, 4, 0, 0x1800, 0x100, 0x100)))
    add('reject-large', 'rejected', build(extra_load=(PT_LOAD, 4, 0, 0x100000, 0, 512 << 20)))
    add('reject-wrap', 'rejected', build(extra_load=(PT_LOAD, 4, 0, (1 << 64) - 0x100, 0, 0x200)))
    # Randomized records.
    rng = random.Random(0x5eed)
    type_pool = TYPES + EXTRA_TYPES
    for n in range(120):
        got = rng.choice(['none', 'undef', 'def0', 'defined'])
        count = len(symbols(got))
        tables = []
        for _ in range(rng.randint(1, 3)):
            rows = []
            for _ in range(rng.randint(1, 48)):
                offset = rng.choice([rng.randrange(DATA, DATA_END), rng.randrange(TEXT, DATA),
                                     rng.randrange(DATA_END, BSS_END), rng.randrange(BSS_END - 8, BSS_END + 8),
                                     rng.choice([f for f, _ in CODE]), rng.randrange(0, 1 << 64)])
                symbol = rng.choice(list(range(count)) + [count + 1, -1])
                addend = rng.choice([0, 1, -1, -4, rng.randrange(-(1 << 31), 1 << 31),
                                     rng.randrange(-(1 << 63), 1 << 63)])
                rows.append((offset, info(symbol, rng.choice(type_pool)), addend))
            tables.append((rng.choice(['rela', 'rela', 'rel']), rows, rng.choice([1, 1, 1, 0]), 0))
        adjust = rng.choice([0x100000, 0x100000, 0, 0x555555554000, 0x7fff0000])
        add(f'random-{n:03d}', 'random', build(tables, got=got, dynamic=rng.choice([None, [(DT_PLTGOT, 0x1f80)]])),
            adjust=adjust, unresolved=rng.random() < 0.2)
    return out


def generate(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    manifest = []
    for case in cases():
        path = output / (case['name'] + '.elf')
        path.write_bytes(case['data'])
        manifest.append(dict(file=path.name, group=case['group'], adjust=f"{case['adjust']:x}",
                             unresolved=case['unresolved'], note=case['note'], length=len(case['data']),
                             sha256=hashlib.sha256(case['data']).hexdigest()))
    return dict(schema=1, cases=manifest)


if __name__ == '__main__':
    import sys
    print(json.dumps(generate(sys.argv[1]), indent=2))
