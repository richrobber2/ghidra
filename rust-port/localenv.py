"""Locations of the Ghidra checkout and toolchains used by the rust-port scripts.

The scripts were first run in a sandbox with everything under /workspace. Each
location can be overridden from the environment; the defaults suit this port
living inside a Ghidra checkout with Java and Cargo on PATH.

  GHIDRA_SRC     Ghidra source checkout (default: the parent of rust-port/)
  JAVA_HOME      JDK whose bin/ holds java and javac (default: javac on PATH)
  CARGO_HOME     Cargo installation whose bin/ is put first on PATH (optional)
  GHIDRA_AGENT   ghidra-agent checkout, only for the lower-level/reference runs
"""
import os
import shutil
from pathlib import Path

PORT = Path(__file__).resolve().parent
GHIDRA = Path(os.environ.get('GHIDRA_SRC', PORT.parent)).resolve()
GHIDRA_AGENT = Path(os.environ.get('GHIDRA_AGENT', '/workspace/ghidra-agent'))
DECOMPILE_ENGINE = GHIDRA / 'Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile'

# Former sandbox locations, used to read paths recorded by earlier runs.
_LEGACY = {'/workspace/ghidra-rust-port': PORT, '/workspace/ghidra': GHIDRA}


def _java_bin():
    if os.environ.get('JAVA_HOME'):
        return Path(os.environ['JAVA_HOME']) / 'bin'
    javac = shutil.which('javac')
    return Path(javac).resolve().parent if javac else Path('/usr/bin')


JAVA = _java_bin()


def cargo_env(env):
    """Put CARGO_HOME/bin first on PATH when CARGO_HOME is set; returns env."""
    if env.get('CARGO_HOME'):
        env['PATH'] = str(Path(env['CARGO_HOME']) / 'bin') + os.pathsep + env['PATH']
    return env


def tool(name, env):
    """Resolve a toolchain executable on env's PATH, e.g. cargo or rustc."""
    return shutil.which(name, path=env.get('PATH')) or name


def resolve(recorded):
    """Map a path recorded under the old /workspace layout to this checkout."""
    text = str(recorded)
    for prefix, root in _LEGACY.items():
        if text == prefix or text.startswith(prefix + '/'):
            return root / text[len(prefix) + 1:]
    return Path(text)


def snapshot_path(path):
    """Stable relative location of a source file inside a results snapshot."""
    path = resolve(path).resolve()
    for root, label in ((PORT, 'ghidra-rust-port'), (GHIDRA, 'ghidra')):
        try:
            return Path(label) / path.relative_to(root)
        except ValueError:
            pass
    return Path('external') / path.name
