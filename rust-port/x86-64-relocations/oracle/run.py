"""Compile and run the original-Java x86-64 relocation oracle over a manifest.

The oracle needs Ghidra's built jars (`./gradlew jar generateLibraryDependencyMapping`).
They are taken from GHIDRA_BUILD when set, else from the Ghidra checkout, else,
when that checkout is a git worktree with no build of its own, from the main
checkout the worktree belongs to.
"""
from pathlib import Path
import argparse
import hashlib
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from localenv import GHIDRA, JAVA  # noqa: E402

MAIN_CLASS = 'ghidra.app.util.bin.format.elf.relocation.X86_64RelocationOracle'
SOURCE = ROOT / 'oracle/X86_64RelocationOracle.java'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ghidra_build():
    """The checkout whose build/ and Ghidra/**/build/libs hold the jars."""
    if os.environ.get('GHIDRA_BUILD'):
        return Path(os.environ['GHIDRA_BUILD']).resolve()
    if (GHIDRA / 'build/libraryDependencies.txt').is_file():
        return GHIDRA
    result = subprocess.run(['git', 'rev-parse', '--path-format=absolute', '--git-common-dir'],
                            cwd=GHIDRA, capture_output=True, text=True)
    if result.returncode == 0:
        main = Path(result.stdout.strip()).parent
        if (main / 'build/libraryDependencies.txt').is_file():
            return main
    raise RuntimeError('No Ghidra jar build found; run ./gradlew jar generateLibraryDependencyMapping '
                       'or set GHIDRA_BUILD')


def classpath(build):
    jars = sorted(build.glob('Ghidra/**/build/libs/*.jar'))
    jars += [Path(s.strip()) for s in (build / 'build/libraryDependencies.txt').read_text().splitlines()
             if s.strip().endswith('.jar') and Path(s.strip()).is_file()]
    return list(dict.fromkeys(jars))


def compile_oracle(classes, timeout=180):
    """Returns (classpath string, jar list, build checkout)."""
    build = ghidra_build()
    jars = classpath(build)
    if not any(jar.name == 'x86.jar' for jar in jars) or not any(jar.name == 'Base.jar' for jar in jars):
        raise RuntimeError(f'x86.jar or Base.jar missing under {build}')
    cp = os.pathsep.join(map(str, jars))
    Path(classes).mkdir(parents=True, exist_ok=True)
    result = subprocess.run([JAVA / 'javac', '-nowarn', '-cp', cp, '-d', classes, SOURCE],
                            capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError('javac failed:\n' + result.stderr.decode(errors='replace')[-4000:])
    return cp, jars, build


def run_oracle(cp, classes, manifest, output, digest=False, timeout=1800):
    command = [JAVA / 'java', '-Xmx4g', '-cp', str(classes) + os.pathsep + cp, MAIN_CLASS]
    if digest:
        command.append('--digest')
    command += [manifest, output]
    return subprocess.run(list(map(str, command)), capture_output=True, timeout=timeout)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path, help='lines: path TAB adjust-hex TAB 0|1')
    parser.add_argument('output', type=Path)
    parser.add_argument('--classes', type=Path, required=True)
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    cp, jars, build = compile_oracle(args.classes)
    result = run_oracle(cp, args.classes, args.manifest, args.output, args.digest)
    sys.stderr.buffer.write(result.stderr)
    print(f'exit {result.returncode}; {len(jars)} jars from {build}')
    sys.exit(result.returncode)
