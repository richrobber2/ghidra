"""Generate small bounded ELF header inputs; no executable payloads."""
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'fixtures'
OUT.mkdir(exist_ok=True)

def header(bits=64, endian='<', **changes):
    fields = dict(type=2, machine=62 if bits == 64 else 3, version=1,
                  entry=0x12345678, phoff=0, shoff=0, flags=0x80000001,
                  ehsize=64 if bits == 64 else 52, phentsize=56 if bits == 64 else 32,
                  phnum=0, shentsize=64 if bits == 64 else 40, shnum=0, shstrndx=0)
    fields.update(changes)
    ident = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2, 1, 0, 0]) + bytes(7)
    return ident + struct.pack(endian + ('HHIQQQIHHHHHH' if bits == 64 else 'HHIIIIIHHHHHH'), *fields.values())

def save(name, data): (OUT / (name+'.elf')).write_bytes(data)

for bits in (32,64):
    for endian in ('<','>'):
        save(f'valid-{bits}-'+('le' if endian=='<' else 'be'), header(bits,endian))
for length in (0,3,4,16,33,34,51,52,63):
    save(f'truncated-{length}',header()[:length])
save('bad-magic',b'NOPE'+header()[4:])
data=bytearray(header()); data[4]=3; save('invalid-class',data)
data=bytearray(header()); data[5]=0; save('invalid-data',data)
data=bytearray(header()); data[5]=2; save('declared-be-actual-le',data)
data=bytearray(header(version=0)); data[6]=0; save('zero-versions',data)
save('zero-header-size',header(ehsize=0))
save('noncanonical-entry-sizes',header(phentsize=1,shentsize=1))
save('unsigned-32',header(32,entry=0xffffffff,phoff=0xfffffffe))
save('unsigned-64',header(entry=0xffffffffffffffff,phoff=0xfffffffffffffffe))
save('str-index-without-sections',header(shstrndx=8))
for bits in (32,64):
    for endian in ('<','>'):
        section=struct.pack(endian+('IIQQQQIIQQ' if bits==64 else 'IIIIIIIIII'),0,0,0,0,0,3,1,2,0,0)
        save(f'extended-{bits}-'+('le' if endian=='<' else 'be'),header(bits,endian,shoff=64 if bits==64 else 52,phnum=0xffff,shnum=0,shstrndx=0xffff)+section)
save('extended-missing-section0',header(shoff=4096,phnum=0xffff,shstrndx=0xffff))
save('extended-overflow',header(shoff=64,phnum=0xffff,shstrndx=0xffff)+struct.pack('<IIQQQQIIQQ',0,0,0,0,0,0x80000000,0x80000000,0x80000000,0,0))
save('reserved-shnum',header(shoff=64,shnum=0xff00)+struct.pack('<IIQQQQIIQQ',0,0,0,0,0,3,1,2,0,0))
print(f'Generated {len(list(OUT.glob("*.elf")))} header fixtures')
