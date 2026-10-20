"""Run the unchanged original Java ELF parsers, in parse() order up to the relocation tables."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from fixtures import generate

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from localenv import GHIDRA, JAVA  # noqa: E402


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = generate(output / 'fixtures')
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    classes = output / 'classes'
    classes.mkdir()
    jars = sorted(GHIDRA.glob('Ghidra/**/build/libs/*.jar'))
    jars += [Path(s.strip()) for s in (GHIDRA / 'build/libraryDependencies.txt').read_text().splitlines()
             if s.strip().endswith('.jar') and Path(s.strip()).is_file()]
    jars = list(dict.fromkeys(jars))
    cp = os.pathsep.join(map(str, jars))
    source = ROOT / 'oracle/ElfRelocationsOracle.java'
    provenance = dict(schema=1, started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                      wrapper_bounds=dict(program_headers=4096, section_headers=65536, dynamic_entries=65536,
                                          symbols_per_table=1_000_000, total_symbols=4_000_000,
                                          relocations_per_table=1_000_000, total_relocations=4_000_000), full_parse_invoked=False,
                      java=str(JAVA), classpath=[dict(path=str(p), sha256=sha(p)) for p in jars],
                      sources={str(p): sha(p) for p in [source, Path(__file__), ROOT / 'oracle/fixtures.py',
                          ROOT.parent / 'dynamic-table/oracle/fixtures.py',
                          *[GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf' / name
                            for name in ('ElfDynamicTable.java', 'ElfDynamic.java', 'ElfProgramHeader.java',
                                         'ElfRelocationTable.java', 'ElfRelocation.java')],
                          GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfHeader.java',
                          GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfSectionHeader.java',
                          GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfCompressedSectionHeader.java',
                          GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfStringTable.java',
                          GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfSymbolTable.java',
                          GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfSymbol.java',
                          GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/UnlimitedByteProviderWrapper.java']},
                      manifest_sha256=sha(output / 'manifest.json'), commands=[])
    (output / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')

    def command(name, args, timeout):
        entry = dict(name=name, argv=list(map(str, args)), timeout_seconds=timeout)
        provenance['commands'].append(entry)
        try:
            result = subprocess.run(entry['argv'], capture_output=True, timeout=timeout)
            entry.update(returncode=result.returncode, timed_out=False)
            stdout, stderr = result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            entry.update(returncode=None, timed_out=True)
        (output / (name + '.stdout')).write_bytes(stdout)
        (output / (name + '.stderr')).write_bytes(stderr)
        entry.update(stdout_sha256=sha(output / (name + '.stdout')),
                     stderr_sha256=sha(output / (name + '.stderr')))
        (output / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
        if entry['timed_out'] or entry['returncode'] != 0:
            raise RuntimeError(f'{name} failed; preserved raw output and status at {output}')
        return stdout

    try:
        command('compile', [JAVA / 'javac', '-cp', cp, '-d', classes, source], 90)
        paths = [output / 'fixtures' / case['file'] for case in manifest['cases']]
        stdout = command('oracle', [JAVA / 'java', '-Xmx2g', '-cp', str(classes) + os.pathsep + cp,
                                    'ElfRelocationsOracle', *paths], 300)
        rows = json.loads(stdout)
        if not isinstance(rows, list) or [row.get('file') for row in rows] != [p.name for p in paths]:
            raise RuntimeError('oracle response inventory differs from the frozen fixture manifest')
        for row in rows:
            if type(row.get('accepted')) is not bool or not isinstance(row.get('warnings'), list):
                raise RuntimeError('invalid oracle result schema')
            if row['accepted'] and any(len(t['relocations']) != t['relocation_count']
                                       for t in row['relocation_tables']):
                raise RuntimeError('accepted relocation count mismatch')
        (output / 'baseline.json').write_text(json.dumps(rows, indent=2) + '\n')
        provenance.update(status='pass', case_count=len(rows), baseline_sha256=sha(output / 'baseline.json'))
    except Exception as error:
        provenance.update(status='failed', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        provenance['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        (output / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    return provenance


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.output)
    print(f"PASS: {result['case_count']} original relocation-table parser cases; {len(result['classpath'])} classpath jars; {args.output}")
