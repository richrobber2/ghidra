"""Run the unchanged original Java ELF program-header table parser in isolation."""
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
GHIDRA = Path('/workspace/ghidra')
JAVA = Path('/workspace/toolchains/jdk-25.0.4.1/bin')


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
    source = ROOT / 'oracle/ElfProgramHeadersOracle.java'
    provenance = dict(schema=1, started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                      wrapper_bound=4096, full_parse_invoked=False,
                      java=str(JAVA), classpath=[dict(path=str(p), sha256=sha(p)) for p in jars],
                      sources={str(p): sha(p) for p in [source, Path(__file__), ROOT / 'oracle/fixtures.py',
                          GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfHeader.java',
                          GHIDRA / 'Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/elf/ElfProgramHeader.java',
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
        stdout = command('oracle', [JAVA / 'java', '-Xmx512m', '-cp', str(classes) + os.pathsep + cp,
                                    'ElfProgramHeadersOracle', *paths], 90)
        rows = json.loads(stdout)
        if not isinstance(rows, list) or [row.get('file') for row in rows] != [p.name for p in paths]:
            raise RuntimeError('oracle response inventory differs from the frozen fixture manifest')
        for row in rows:
            if type(row.get('accepted')) is not bool or not isinstance(row.get('warnings'), list):
                raise RuntimeError('invalid oracle result schema')
            if row['accepted'] and len(row['entries']) != row['phnum']:
                raise RuntimeError('accepted table entry count mismatch')
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
    print(f"PASS: {result['case_count']} original private-parser cases; {len(result['classpath'])} classpath jars; {args.output}")
