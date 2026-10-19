"""Deterministic, bounded ELF relocation-table fixtures; no executable payloads.

The images extend the dynamic-table fixtures (../dynamic-table/oracle/fixtures.py):
one PT_LOAD over the first 0x2000 bytes, the same dynamic symbol, string and hash
tables, and relocation tables at REL_A, REL_B and RELR_AT. Generation only creates
a fresh directory, and every byte is recorded before Java or Rust sees the corpus.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import random
import struct

_SPEC = importlib.util.spec_from_file_location(
    'dynamic_fixtures', Path(__file__).resolve().parents[2] / 'dynamic-table/oracle/fixtures.py')
base = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(base)

BASE, LONG_MAX, SHNAME = base.BASE, base.LONG_MAX, base.SHNAME
DT_NULL = base.DT_NULL
PT_LOAD = base.PT_LOAD
FILE_END = 0x2000
REL_A, REL_B, RELR_AT = 0x1000, 0x1400, 0x1800

DT_PLTRELSZ, DT_RELA, DT_RELASZ, DT_RELAENT = 2, 7, 8, 9
DT_REL, DT_RELSZ, DT_RELENT, DT_PLTREL, DT_JMPREL = 17, 18, 19, 20, 23
DT_RELRSZ, DT_RELR, DT_RELRENT = 35, 36, 37
DT_ANDROID_REL, DT_ANDROID_RELSZ = 0x6000000f, 0x60000010
DT_ANDROID_RELA, DT_ANDROID_RELASZ = 0x60000011, 0x60000012
DT_ANDROID_RELR, DT_ANDROID_RELRSZ, DT_ANDROID_RELRENT = 0x6fffe000, 0x6fffe001, 0x6fffe003
SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_REL, SHT_DYNSYM, SHT_RELR = 2, 3, 4, 9, 11, 19
SHT_ANDROID_REL, SHT_ANDROID_RELA, SHT_ANDROID_RELR = 0x60000001, 0x60000002, 0x6fffff00
SHF_ALLOC = 2


def rel_size(bits, addend):
    return (24 if addend else 16) if bits == 64 else (12 if addend else 8)


def relocs(bits, endian, rows, addend):
    out = bytearray()
    for row in rows:
        offset, info = row[0], row[1]
        value = row[2] if len(row) > 2 else 0
        if bits == 64:
            out += struct.pack(endian + 'QQ', offset, info)
            if addend:
                out += struct.pack(endian + 'q', value)
        else:
            out += struct.pack(endian + 'II', offset, info)
            if addend:
                out += struct.pack(endian + 'i', value)
    return bytes(out)


def standard_rows(bits, count=3, start=0x600):
    if bits == 64:
        return [(BASE + start + 8 * i, ((i + 1) << 32) | 7, i * 16 - 8) for i in range(count)]
    return [(BASE + start + 4 * i, ((i + 1) << 8) | 7, i * 16 - 8) for i in range(count)]


def relr_words(bits, endian, words):
    return struct.pack(endian + ('Q' if bits == 64 else 'I') * len(words), *words)


def standard_relr(bits):
    word = 8 if bits == 64 else 4
    return [BASE + 0x600, 0b1011, BASE + 0x700, 1 | (0x55 << 1), BASE + 0x600 + 2 * word]


def reloc_image(bits, endian, entries=(), dynamic=None, sections=True, extra_sections=(), blobs=(),
                load=None, **kw):
    """Dynamic entries are inserted before DT_NULL; sections 7.. come from extra_sections."""
    if dynamic is None:
        dynamic = base.default_dynamic(bits)[:-1] + list(entries) + [(DT_NULL, 0)]
    load_values = dict(filesz=FILE_END)
    load_values.update(load or {})
    blobs = list(blobs) + [(FILE_END - 1, b'\0')]
    return base.image(bits, endian, dynamic=dynamic, sections=sections, extra_sections=list(extra_sections),
                      blobs=blobs, load=load_values, **kw)


def rela_section(bits, offset=REL_A, count=3, kind=SHT_RELA, name='.other', **changes):
    addend = kind in (SHT_RELA, SHT_ANDROID_RELA)
    values = dict(name=name, type=kind, flags=SHF_ALLOC, addr=BASE + offset, offset=offset,
                  size=count * rel_size(bits, addend), link=1, info=0, align=8,
                  entsize=rel_size(bits, addend))
    values.update(changes)
    return values


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
            word = 8 if bits == 64 else 4
            ra, rr = rel_size(bits, True), rel_size(bits, False)
            rows = standard_rows(bits)
            rela = relocs(bits, endian, rows, True)
            rel = relocs(bits, endian, rows, False)
            plt = relocs(bits, endian, standard_rows(bits, 2, 0x680), True)
            relr = relr_words(bits, endian, standard_relr(bits))
            ns = dict(sections=False)
            rela_dyn = [(DT_RELA, BASE + REL_A), (DT_RELASZ, len(rela)), (DT_RELAENT, ra)]
            rel_dyn = [(DT_REL, BASE + REL_A), (DT_RELSZ, len(rel)), (DT_RELENT, rr)]
            jmp_dyn = [(DT_JMPREL, BASE + REL_B), (DT_PLTRELSZ, len(plt)), (DT_PLTREL, DT_RELA)]
            relr_dyn = [(DT_RELR, BASE + RELR_AT), (DT_RELRSZ, len(relr)), (DT_RELRENT, word)]
            all_dyn = rela_dyn + jmp_dyn + relr_dyn
            all_blobs = [(REL_A, rela), (REL_B, plt), (RELR_AT, relr)]
            all_sections = [rela_section(bits), rela_section(bits, REL_B, 2, info=5, name=''),
                            rela_section(bits, RELR_AT, kind=SHT_RELR, size=len(relr), entsize=word, link=0)]

            def case(name, group, **kw):
                save(f'{name}-{tag}', reloc_image(bits, endian, **kw), group)

            # Canonical shared objects and relocatable-style sections.
            case('canonical', 'canonical', entries=all_dyn, blobs=all_blobs, extra_sections=all_sections)
            case('canonical-no-sections', 'canonical', entries=all_dyn, blobs=all_blobs, **ns)
            case('canonical-rel', 'canonical', entries=rel_dyn, blobs=[(REL_A, rel)],
                 extra_sections=[rela_section(bits, kind=SHT_REL)])
            case('canonical-rel-no-sections', 'canonical', entries=rel_dyn + [
                (DT_JMPREL, BASE + REL_B), (DT_PLTRELSZ, 2 * rr), (DT_PLTREL, DT_REL)],
                 blobs=[(REL_A, rel), (REL_B, rel[:2 * rr])], **ns)
            case('canonical-relr-only', 'canonical', entries=relr_dyn, blobs=[(RELR_AT, relr)], **ns)
            case('canonical-section-only', 'canonical', blobs=[(REL_A, rela)],
                 extra_sections=[rela_section(bits, flags=0, addr=0, info=5)])
            case('canonical-no-relocations', 'canonical')
            case('canonical-symtab-link', 'canonical', blobs=[(REL_A, rela)],
                 extra_sections=[rela_section(bits, flags=0, addr=0, link=7 + 1),
                                 dict(name='.symtab', type=SHT_SYMTAB, offset=base.DYNSYM, size=5 * base.entsize(bits),
                                      link=2, info=1, entsize=base.entsize(bits))])

            # Finding dynamic tables.
            case('dyn-unloaded', 'dynamic-tables', entries=[(DT_RELA, 0x900000)] + rela_dyn[1:], **ns)
            case('dyn-zero', 'dynamic-tables', entries=[(DT_RELA, 0)] + rela_dyn[1:], **ns)
            case('dyn-missing-size', 'dynamic-tables', entries=rela_dyn[::2], blobs=[(REL_A, rela)], **ns)
            case('dyn-missing-entsize', 'dynamic-tables', entries=rela_dyn[:2], blobs=[(REL_A, rela)], **ns)
            case('dyn-duplicate-tag', 'dynamic-tables', entries=[(DT_RELA, BASE + REL_B)] + rela_dyn,
                 blobs=[(REL_A, rela), (REL_B, plt)], **ns)
            for value in (0, 1, ra - 1, ra + 8, 0x100):
                case(f'dyn-entsize-{value:x}', 'dynamic-tables',
                     entries=[*rela_dyn[:2], (DT_RELAENT, value)], blobs=[(REL_A, rela)], **ns)
            case('dyn-size-not-multiple', 'dynamic-tables', entries=[rela_dyn[0], (DT_RELASZ, len(rela) + 5),
                                                                     rela_dyn[2]], blobs=[(REL_A, rela)], **ns)
            case('dyn-past-eof', 'dynamic-tables', entries=[(DT_RELA, BASE + FILE_END - ra), (DT_RELASZ, 40 * ra),
                                                            rela_dyn[2]], load=dict(memsz=0x10000), **ns)
            if bits == 64:
                case('dyn-entsize-negative', 'dynamic-tables',
                     entries=[*rela_dyn[:2], (DT_RELAENT, (1 << 64) - 24)], blobs=[(REL_A, rela)], **ns)
                case('dyn-size-negative', 'dynamic-tables',
                     entries=[rela_dyn[0], (DT_RELASZ, 1 << 63), rela_dyn[2]], blobs=[(REL_A, rela)], **ns)
                case('dyn-size-int-wrap', 'dynamic-tables',
                     entries=[rela_dyn[0], (DT_RELASZ, (1 << 32) * 24), rela_dyn[2]], blobs=[(REL_A, rela)], **ns)
                case('dyn-negative-offset', 'dynamic-tables', entries=[(DT_RELA, 0x500000)] + rela_dyn[1:],
                     extra_segments=[dict(type=PT_LOAD, offset=1 << 63, vaddr=0x500000, filesz=0x100)], **ns)
                case('dyn-near-long-max', 'dynamic-tables', entries=[(DT_RELA, 0x500000)] + rela_dyn[1:],
                     extra_segments=[dict(type=PT_LOAD, offset=LONG_MAX - 30, vaddr=0x500000, filesz=0x100)], **ns)
            case('dyn-in-bss', 'dynamic-tables', entries=[(DT_RELA, 0x500010)] + rela_dyn[1:],
                 extra_segments=[dict(type=PT_LOAD, offset=0x1000, vaddr=0x500000, filesz=0, memsz=0x1000)], **ns)
            case('dyn-invalid-load-offset', 'dynamic-tables', entries=[(DT_RELA, 0x500010)] + rela_dyn[1:],
                 extra_segments=[dict(type=PT_LOAD, offset=(1 << bits) - 1, vaddr=0x500000, filesz=0x100)], **ns)
            case('dyn-rel-and-rela-same', 'dynamic-tables', entries=rela_dyn + [
                (DT_REL, BASE + REL_A), (DT_RELSZ, len(rel)), (DT_RELENT, rr)], blobs=[(REL_A, rela)], **ns)
            case('prelink', 'dynamic-tables', entries=all_dyn, blobs=all_blobs, extra_sections=all_sections,
                 tail=struct.pack(endian + 'I', 0x10000000) + b'PRE ')
            case('prelink-no-sections', 'dynamic-tables', entries=all_dyn, blobs=all_blobs,
                 tail=struct.pack(endian + 'I', 0x10000000) + b'PRE ', **ns)

            # DT_JMPREL and DT_PLTREL.
            case('jmprel-rel', 'jmprel', entries=jmp_dyn[:2] + [(DT_PLTREL, DT_REL), (DT_RELENT, rr)],
                 blobs=[(REL_B, plt)], **ns)
            case('jmprel-pltrel-other', 'jmprel', entries=jmp_dyn[:2] + [(DT_PLTREL, 5)], blobs=[(REL_B, plt)], **ns)
            case('jmprel-no-pltrel', 'jmprel', entries=jmp_dyn[:2], blobs=[(REL_B, plt)], **ns)
            case('jmprel-no-size', 'jmprel', entries=jmp_dyn[::2], blobs=[(REL_B, plt)], **ns)
            case('jmprel-relaent', 'jmprel', entries=jmp_dyn + [(DT_RELAENT, ra + 8)], blobs=[(REL_B, plt)], **ns)
            case('jmprel-same-as-rela', 'jmprel', entries=rela_dyn + [(DT_JMPREL, BASE + REL_A),
                                                                     (DT_PLTRELSZ, len(rela)), (DT_PLTREL, DT_RELA)],
                 blobs=[(REL_A, rela)], **ns)
            case('jmprel-unloaded', 'jmprel', entries=[(DT_JMPREL, 0x900000)] + jmp_dyn[1:], **ns)

            # Dynamic addresses inside sections, and section tables.
            case('dyn-in-other-section', 'sections', entries=[(DT_RELA, BASE + base.DYNSTR)] + rela_dyn[1:],
                 blobs=[(REL_A, rela)])
            case('dyn-inside-section', 'sections', entries=[(DT_RELA, BASE + REL_A + ra)] + rela_dyn[1:],
                 blobs=[(REL_A, rela)], extra_sections=[rela_section(bits)])
            case('dyn-rel-in-rela-section', 'sections', entries=rel_dyn, blobs=[(REL_A, rela)],
                 extra_sections=[rela_section(bits)])
            case('dyn-section-not-alloc', 'sections', entries=rela_dyn, blobs=[(REL_A, rela)],
                 extra_sections=[rela_section(bits, flags=0)])
            for name, changes in [('info-invalid', dict(info=99)), ('info-negative', dict(info=0x80000000)),
                                  ('link-invalid', dict(link=99)), ('link-strtab', dict(link=2)),
                                  ('link-zero', dict(link=0)), ('entsize-zero', dict(entsize=0)),
                                  ('entsize-odd', dict(entsize=ra + 3)), ('size-odd', dict(size=3 * ra + 1)),
                                  ('size-zero', dict(size=0)), ('past-eof', dict(offset=FILE_END - ra, size=8 * ra)),
                                  ('invalid-offset', dict(offset=(1 << bits) - 1)),
                                  ('named-dynsym', dict(name='.dynsym'))]:
                case(f'section-{name}', 'sections', blobs=[(REL_A, rela)],
                     extra_sections=[rela_section(bits, **{**dict(flags=0, addr=0, info=5), **changes})])
            case('section-link-zero-no-dynsym', 'sections', blobs=[(REL_A, rela)], drop_sections=('.dynsym',),
                 extra_sections=[rela_section(bits, flags=0, addr=0, link=0)])
            case('section-link-zero-two-dynsym', 'sections', blobs=[(REL_A, rela)],
                 extra_sections=[rela_section(bits, flags=0, addr=0, link=0),
                                 dict(name='.dynsym', type=SHT_DYNSYM, offset=base.DYNSYM, size=24, entsize=24)])
            case('section-symbol-table-missing', 'sections', blobs=[(REL_A, rela)],
                 extra_sections=[rela_section(bits, flags=0, addr=0, link=8),
                                 dict(name='.symtab', type=SHT_SYMTAB, offset=0x1f00, size=0, entsize=24)])
            case('section-duplicate-offset', 'sections', blobs=[(REL_A, rela)],
                 extra_sections=[rela_section(bits, flags=0), rela_section(bits, flags=0, kind=SHT_REL)])
            case('section-rel', 'sections', blobs=[(REL_A, rel)],
                 extra_sections=[rela_section(bits, kind=SHT_REL, flags=0, addr=0)])
            case('section-relr', 'sections', blobs=[(RELR_AT, relr)],
                 extra_sections=[rela_section(bits, RELR_AT, kind=SHT_RELR, size=len(relr), entsize=word)])
            case('section-android-relr', 'sections', blobs=[(RELR_AT, relr)],
                 extra_sections=[rela_section(bits, RELR_AT, kind=SHT_ANDROID_RELR, size=len(relr), entsize=word)])
            case('section-and-dynamic', 'sections', entries=all_dyn, blobs=all_blobs,
                 extra_sections=all_sections[:1] + [rela_section(bits, REL_B, 2, flags=0, addr=0)])
            if bits == 64:
                case('section-near-long-max', 'sections',
                     extra_sections=[rela_section(bits, flags=0, addr=0, offset=LONG_MAX - 30)])

            # RELR tables.
            def relr_case(name, words, entsize=word, size=None, **kw):
                data = relr_words(bits, endian, words)
                case(f'relr-{name}', 'relr', entries=[(DT_RELR, BASE + RELR_AT),
                                                       (DT_RELRSZ, len(data) if size is None else size),
                                                       (DT_RELRENT, entsize)], blobs=[(RELR_AT, data)], **ns, **kw)

            all_ones = (1 << (8 * word)) - 1
            relr_case('all-ones', [BASE + 0x600, all_ones, all_ones])
            relr_case('odd-first', [BASE + 0x601, 2])
            relr_case('size-zero', [BASE + 0x600], size=0)
            relr_case('size-short', [BASE + 0x600, 3], size=word + 1)
            relr_case('size-not-multiple', [BASE + 0x600, 3, BASE + 0x700], size=2 * word + 3)
            relr_case('entsize-3', [BASE + 0x600, 3, 5], entsize=3)
            relr_case('entsize-other-word', [BASE + 0x600, 3, 5, 7], entsize=12 - word)
            relr_case('entsize-zero', [BASE + 0x600], entsize=0)
            relr_case('wrapping', [(1 << (8 * word)) - word, 0b111])
            if bits == 64:
                relr_case('entsize-negative', [BASE + 0x600], entsize=(1 << 64) - 8)
                relr_case('entsize-huge', [BASE + 0x600, 3], entsize=1 << 62, size=1 << 62)
            data = relr_words(bits, endian, standard_relr(bits))
            case('relr-android', 'relr', entries=[(DT_ANDROID_RELR, BASE + RELR_AT),
                                                  (DT_ANDROID_RELRSZ, len(data)), (DT_ANDROID_RELRENT, word)],
                 blobs=[(RELR_AT, data)], **ns)
            case('relr-and-android-same', 'relr', entries=relr_dyn + [
                (DT_ANDROID_RELR, BASE + RELR_AT), (DT_ANDROID_RELRSZ, len(data)), (DT_ANDROID_RELRENT, word)],
                 blobs=[(RELR_AT, data)], **ns)

            # Resource bounds and Android packed tables, applied by both sides.
            case('android-rela', 'resource-bound', entries=[(DT_ANDROID_RELA, BASE + REL_A),
                                                            (DT_ANDROID_RELASZ, 16)], blobs=[(REL_A, b'APS2')], **ns)
            case('android-rel', 'resource-bound', entries=[(DT_ANDROID_REL, 0x900000)], **ns)
            case('android-section', 'resource-bound', blobs=[(REL_A, b'APS2')],
                 extra_sections=[rela_section(bits, kind=SHT_ANDROID_REL, size=4, entsize=0)])
            case('limit-relocations', 'resource-bound',
                 entries=[rela_dyn[0], (DT_RELASZ, ra * 1_000_001), rela_dyn[2]], **ns)
            case('limit-relocations-unparsed', 'resource-bound',
                 entries=[(DT_RELA, 0x900000), (DT_RELASZ, ra * 1_000_001), rela_dyn[2]], **ns)
            case('limit-relr', 'resource-bound', entries=[(DT_RELR, BASE + RELR_AT), (DT_RELRSZ, word * 20_000),
                                                          (DT_RELRENT, word)], **ns)
            case('limit-total', 'resource-bound', extra_sections=[
                rela_section(bits, offset=0x1f00 - i, count=900_000, flags=0, addr=0) for i in range(5)])
            case('relocations-zero-filled', 'resource-bound',
                 entries=[(DT_RELA, BASE + FILE_END - ra), (DT_RELASZ, ra * 5000), rela_dyn[2]],
                 load=dict(memsz=0x100000), **ns)

            # Recovery inherited from earlier components.
            data = bytearray(reloc_image(bits, endian, entries=all_dyn, blobs=all_blobs))
            data[5] = 0 if endian == '<' else 3
            save(f'encoding-{tag}', bytes(data), 'header')
            save(f'truncated-section-table-{tag}',
                 reloc_image(bits, endian, entries=all_dyn, blobs=all_blobs,
                             extra_sections=all_sections)[:base.SHOFF + 3 * (64 if bits == 64 else 40)], 'header')

    # Randomized relocation entries and sections.
    rng = random.Random(0x7e1)
    tags = [DT_REL, DT_RELSZ, DT_RELENT, DT_RELA, DT_RELASZ, DT_RELAENT, DT_JMPREL, DT_PLTRELSZ, DT_PLTREL,
            DT_RELR, DT_RELRSZ, DT_RELRENT]
    for seed in range(24):
        bits, endian = ((64, '<'), (32, '>'), (64, '>'), (32, '<'))[seed % 4]
        word = 8 if bits == 64 else 4
        entries = []
        for _ in range(rng.randint(1, 9)):
            tag = rng.choice(tags)
            choice = rng.random()
            if tag in (DT_REL, DT_RELA, DT_JMPREL, DT_RELR) and choice < 0.7:
                value = BASE + rng.choice((REL_A, REL_B, RELR_AT, base.DYNSTR, rng.randrange(0, FILE_END)))
            elif tag == DT_PLTREL and choice < 0.8:
                value = rng.choice((DT_REL, DT_RELA))
            elif choice < 0.85:
                value = rng.choice((0, 1, 3, 4, 8, 12, 16, 24, 48, 72, 0x100, 0x401))
            else:
                value = rng.getrandbits(bits)
            entries.append((tag, value))
        blobs = [(REL_A, bytes(rng.getrandbits(8) for _ in range(0x100))),
                 (REL_B, bytes(rng.getrandbits(8) for _ in range(0x80))),
                 (RELR_AT, relr_words(bits, endian, [rng.getrandbits(8 * word) for _ in range(8)]))]
        extra = []
        for _ in range(rng.randint(0, 3)):
            kind = rng.choice((SHT_REL, SHT_RELA, SHT_RELR, SHT_ANDROID_RELR, SHT_STRTAB))
            extra.append(dict(name=rng.choice(('', '.other', '.dynsym')), type=kind,
                              flags=rng.choice((0, SHF_ALLOC)), addr=BASE + rng.choice((REL_A, REL_B, RELR_AT)),
                              offset=rng.choice((REL_A, REL_B, RELR_AT, 0x1f00)),
                              size=rng.choice((0, 8, 24, 48, 0x100, 0x1000)), link=rng.choice((0, 1, 2, 9)),
                              info=rng.choice((0, 5, 12)), entsize=rng.choice((0, word, 12, 16, 24))))
        save(f'random-{bits}-{seed}', reloc_image(bits, endian, entries=entries, blobs=blobs, extra_sections=extra,
                                                  sections=rng.random() < 0.6), 'randomized')

    cases.sort(key=lambda x: x['file'])
    manifest = dict(schema=1, resource_bounds=dict(program_headers=4096, section_headers=65536,
                                                   dynamic_entries=65536, symbols_per_table=1_000_000,
                                                   total_symbols=4_000_000, relocations_per_table=1_000_000,
                                                   total_relocations=4_000_000),
                    purpose='Original ELF relocation-table parity.',
                    cases=cases, groups={group: sum(c['group'] == group for c in cases)
                                         for group in sorted({c['group'] for c in cases})})
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = generate(args.output)
    print(f"Generated {len(manifest['cases'])} immutable relocation-table fixtures at {args.output}")
