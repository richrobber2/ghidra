"""Compile and execute the original Java parser against the bounded fixture corpus."""
from pathlib import Path
import json, os, subprocess

ROOT=Path(__file__).resolve().parents[1]
GHIDRA=Path('/workspace/ghidra')
JAVA=Path('/workspace/toolchains/jdk-25.0.4.1/bin')
subprocess.run(['python3',str(ROOT/'oracle/fixtures.py')],check=True)
classes=ROOT/'oracle/classes'; classes.mkdir(exist_ok=True)
jars=sorted(GHIDRA.glob('Ghidra/**/build/libs/*.jar'))
jars += [Path(s.strip()) for s in (GHIDRA/'build/libraryDependencies.txt').read_text().splitlines()
         if s.strip().endswith('.jar') and Path(s.strip()).is_file()]
cp=os.pathsep.join(map(str,dict.fromkeys(jars)))
subprocess.run([str(JAVA/'javac'),'-cp',cp,'-d',str(classes),str(ROOT/'oracle/ElfHeaderOracle.java')],check=True)
files=sorted((ROOT/'fixtures').glob('*.elf'))
result=subprocess.run([str(JAVA/'java'),'-cp',str(classes)+os.pathsep+cp,'ElfHeaderOracle',*map(str,files)],text=True,capture_output=True,check=True,timeout=30)
rows=json.loads(result.stdout)
out=ROOT/'results'; out.mkdir(exist_ok=True)
(out/'java-header-baseline.json').write_text(json.dumps(rows,indent=2)+'\n')
by_name={r['file']:r for r in rows}
for bits in (32,64):
    for endian in ('le','be'):
        r=by_name[f'valid-{bits}-{endian}.elf']
        assert r['accepted'] and r['class_bits']==bits and r['entry_hex']=='12345678'
        assert r['header_little_endian']==(endian=='le')
        r=by_name[f'extended-{bits}-{endian}.elf']
        assert (r['phnum'],r['shnum'],r['shstrndx'])==(2,3,1)
for n in (0,3,4,16,33): assert not by_name[f'truncated-{n}.elf']['accepted']
for n in (34,51,52,63): assert by_name[f'truncated-{n}.elf']['accepted']
assert not by_name['bad-magic.elf']['accepted']
assert not by_name['invalid-class.elf']['accepted']
assert by_name['invalid-data.elf']['accepted'] and by_name['invalid-data.elf']['warnings']
assert by_name['declared-be-actual-le.elf']['header_little_endian']
assert not by_name['declared-be-actual-le.elf']['declared_little_endian']
assert by_name['zero-versions.elf']['accepted']
assert by_name['zero-header-size.elf']['ehsize']==0
assert by_name['noncanonical-entry-sizes.elf']['phentsize']==1
assert by_name['unsigned-32.elf']['entry_hex']=='ffffffff'
assert by_name['unsigned-64.elf']['entry_hex']=='ffffffffffffffff'
assert by_name['str-index-without-sections.elf']['shstrndx']==0
assert by_name['reserved-shnum.elf']['shnum']==3
for name in ('extended-overflow','extended-missing-section0'):
    r=by_name[name+'.elf']; assert (r['phnum'],r['shnum'],r['shstrndx'])==(0,0,0)
print(f'PASS: {len(rows)} source-guided fixtures exercised against the original ElfHeader constructor')
