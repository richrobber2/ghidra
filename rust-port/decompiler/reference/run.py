#!/usr/bin/env python3
"""Compare selected Rust instruction graphs with fresh original Ghidra exports.

Runs serially; outputs must be new. This is a validation/reference workload,
never a benchmark and never a semantic comparison of inferred C text.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent
PORT = ROOT.parent
WRAPPER = Path('/workspace/ghidra-agent/ghidra-agent')
ENGINE = Path('/workspace/ghidra/Ghidra/Features/Decompiler/build/os/linux_x86_64/decompile')
ENGINE_SHA = '876c28d48c07126e5db94946c10719eeb96b057c9271daa0114df34e598f262a'
JOBS = [
    dict(name='c-O2', relative='results/semantics-02/original/scalar-O2.so',
         sha256='97fc0f1e34756f4c8d90cb3e9198d2c01a84c18e9b8a57618b3b7588548f8fb9',
         functions=['add_mix', 'select_signed', 'loop_accumulate']),
    dict(name='rust-O3', relative='results/rust-01/target/librust_kernels.so',
         sha256='3c644a198dc6cfb5abeefb6f09e1e641cb78facddea124abc05de380b2b3e00b',
         functions=['rust_arithmetic', 'rust_branch', 'rust_loop']),
]


def digest(path):
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def record(path):
    return dict(path=str(path), bytes=path.stat().st_size, sha256=digest(path))


class Commands:
    def __init__(self, output):
        self.output = output
        self.rows = []
        (output / 'logs').mkdir()

    def run(self, label, argv, timeout):
        index = len(self.rows)
        stdout = self.output / 'logs' / f'{index:02d}-{label}.stdout'
        stderr = self.output / 'logs' / f'{index:02d}-{label}.stderr'
        row = dict(label=label, argv=[str(arg) for arg in argv],
                   timeout_seconds=timeout, started_unix=time.time(),
                   stdout=str(stdout), stderr=str(stderr), timed_out=False)
        self.rows.append(row)
        started = time.monotonic()
        with stdout.open('wb') as out, stderr.open('wb') as err:
            process = subprocess.Popen(row['argv'], stdout=out, stderr=err,
                                       start_new_session=True)
            try:
                row['returncode'] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row['timed_out'] = True
                os.killpg(process.pid, signal.SIGKILL)
                row['returncode'] = process.wait()
        row['elapsed_seconds'] = time.monotonic() - started
        write_json(self.output / 'commands.json', self.rows)
        if row['timed_out'] or row['returncode'] != 0:
            raise RuntimeError(f'{label}: failed or timed out; see retained logs')
        return stdout, stderr


def instruction_comparison(output, binary, function, rust_output, report, target):
    """Check decoded starts/lengths/bytes and supported direct control flow.

    The matched shared objects have original ELF image base zero. Ghidra's
    chosen import image base is explicitly subtracted before comparing VMAs.
    Inferred C expressions and types are deliberately not compared.
    """
    image_base = int(report['image_base'], 16)
    start = function['address']
    end = start + function['size']
    if int(target['address'], 16) != image_base + start or target['size_bytes'] != function['size']:
        raise ValueError('original Ghidra target extent does not match selected ELF symbol')
    file_offset = function['file_offset']
    file_bytes = binary.read_bytes()
    raw = file_bytes[file_offset:file_offset + function['size']]
    if len(raw) != function['size']:
        raise ValueError('symbol extent exceeds original binary')
    manifest = json.loads((rust_output / 'manifest.json').read_text())
    ir = json.loads((rust_output / 'ir.json').read_text())
    if manifest.get('status') != 'ok' or manifest.get('backend') != 'native-rust':
        raise ValueError('Rust did not produce an accepted native graph')
    if manifest.get('instruction_count') != len(ir) or not ir:
        raise ValueError('Rust graph count does not match manifest')
    ghidra = json.loads((output / 'ghidra' / target['instructions_file']).read_text())
    if target.get('instruction_count') != len(ghidra):
        raise ValueError('original Ghidra instruction count differs from listing')
    rows = {int(row['address'], 16) - image_base: row for row in ghidra}
    if len(rows) != len(ghidra):
        raise ValueError('duplicate original Ghidra instruction starts')
    compared = []
    rust_starts = set()
    for ins in ir:
        address = int(ins['address_hex'], 16)
        if address in rust_starts:
            raise ValueError('duplicate Rust reachable instruction start')
        rust_starts.add(address)
        if not (start <= address and address + ins['size'] <= end):
            raise ValueError('Rust instruction crosses declared symbol extent')
        other = rows.get(address)
        if other is None:
            raise ValueError(f'Ghidra lacks Rust-reachable instruction {address:#x}')
        expected_bytes = raw[address - start:address - start + ins['size']].hex()
        if other['size_bytes'] != ins['size'] or other['bytes_hex'] != expected_bytes:
            raise ValueError(f'instruction size/bytes differ at {address:#x}')
        flows = sorted(int(value, 16) - image_base for value in other['flows'])
        # Gson's default writer omits keys for Java null values (RET/JMP).
        fallthrough = other.get('fallthrough')
        fallthrough = None if fallthrough is None else int(fallthrough, 16) - image_base
        op = ins['op']
        branch = re.fullmatch(r'(Jump|Branch) \{ (?:condition: \w+, )?target: (\d+) \}', op)
        if branch:
            expected_target = int(branch.group(2))
            if flows != [expected_target]:
                raise ValueError(f'direct branch destinations differ at {address:#x}')
            expected_fallthrough = None if branch.group(1) == 'Jump' else address + ins['size']
        elif op == 'Return':
            if flows:
                raise ValueError(f'unexpected return destination at {address:#x}')
            expected_fallthrough = None
        else:
            if flows:
                raise ValueError(f'unexpected non-branch flow at {address:#x}')
            expected_fallthrough = address + ins['size']
        if fallthrough != expected_fallthrough:
            raise ValueError(f'instruction fallthrough differs at {address:#x}')
        compared.append(dict(address_hex=hex(address), size=ins['size'],
                             bytes_hex=expected_bytes, direct_targets_hex=[hex(x) for x in flows],
                             fallthrough_hex=None if fallthrough is None else hex(fallthrough)))
    return dict(function=function['name'], status='matched',
                rust_reachable_instruction_count=len(ir),
                ghidra_instruction_count=len(ghidra),
                ghidra_extra_instruction_starts=[hex(x) for x in sorted(set(rows) - rust_starts)],
                byte_length=sum(row['size'] for row in compared),
                instructions=compared,
                ghidra_decompiler_message=target.get('decompile_error'),
                inferred_c_equivalence_claimed=False)


def validate_export(output, job, command_stdout, command_stderr):
    directory = output / 'ghidra'
    report = json.loads((directory / 'selected.json').read_text())
    log = command_stdout.read_text(errors='replace') + command_stderr.read_text(errors='replace')
    footer = 'SELECTED_EXPORT_OK ' + str(directory / 'selected.json')
    if footer not in log:
        raise ValueError('missing original Ghidra export footer')
    if report.get('export_complete') is not True:
        raise ValueError('incomplete original Ghidra export')
    for name in ['truncated', 'cancelled', 'analysis_timed_out']:
        if report.get(name) is not False:
            raise ValueError('missing/true original Ghidra status: ' + name)
    for name in ['requested_count', 'attempted_count', 'decompiled_count']:
        if report.get(name) != len(job['functions']):
            raise ValueError('original Ghidra export count mismatch: ' + name)
    if report.get('failed_count') != 0 or report.get('selected_only') is not True:
        raise ValueError('original Ghidra export scope/failure mismatch')
    if report.get('automatic_analysis_requested_by_script') is not False:
        raise ValueError('unexpected Ghidra automatic analysis')
    if report.get('timeout_seconds_per_function') != 45:
        raise ValueError('unexpected Ghidra function timeout')
    if report.get('language') != 'x86:LE:64:default':
        raise ValueError('unexpected original Ghidra language')
    if report.get('executable_sha256', '').lower() != job['sha256']:
        raise ValueError('original Ghidra imported executable SHA differs')
    targets = report.get('targets', [])
    if len(targets) != len(job['functions']):
        raise ValueError('original Ghidra target count mismatch')
    for target, name in zip(targets, job['functions']):
        if target.get('label') != name or target.get('status') != 'decompiled':
            raise ValueError('original Ghidra target status/label mismatch')
        for flag in ['decompile_timed_out', 'decompile_cancelled',
                     'decompile_failed_to_start', 'instruction_export_truncated',
                     'instruction_crosses_requested_end']:
            if target.get(flag) is not False:
                raise ValueError('missing/true original Ghidra target flag: ' + flag)
        if target.get('bounded_disassembly_ok') is not True:
            raise ValueError('original Ghidra bounded disassembly failed')
        if not (directory / target['c_file']).is_file() or not (directory / target['c_file']).stat().st_size:
            raise ValueError('missing original Ghidra C export')
    return report, targets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='fresh result directory')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = Commands(output)
    summary = dict(schema=1, status='failed', scope='six selected functions from two exact semantic-test binaries',
                   ghidra_autoanalysis=False, benchmark=False,
                   inferred_c_equivalence_claimed=False, jobs=[], errors=[])
    frozen = []
    try:
        if digest(ENGINE) != ENGINE_SHA:
            raise ValueError('installed original native engine changed')
        frozen.append(record(ENGINE))
        snapshots = output / 'snapshots'
        snapshots.mkdir()
        candidate = snapshots / 'rust-ghidra'
        shutil.copy2(PORT / 'target/release/rust-ghidra', candidate)
        frozen.append(record(candidate))
        source_paths = [Path(__file__), ROOT / 'tools/SelectedExport.java',
                        PORT / 'Cargo.toml', PORT / 'Cargo.lock',
                        *sorted((PORT / 'src').glob('*')),
                        PORT.parent / 'Cargo.toml', PORT.parent / 'src/lib.rs',
                        PORT.parent / 'program-headers/Cargo.toml',
                        PORT.parent / 'program-headers/src/lib.rs']
        source_snapshots = []
        for i, path in enumerate(source_paths):
            target = snapshots / f'{i:02d}-{path.name}'
            shutil.copy2(path, target)
            source_snapshots.append(dict(original=record(path), snapshot=record(target)))
        scripts = snapshots / 'scripts'
        scripts.mkdir()
        shutil.copy2(ROOT / 'tools/SelectedExport.java', scripts / 'SelectedExport.java')
        write_json(output / 'sources.json', source_snapshots)
        summary['provenance'] = dict(engine=record(ENGINE), candidate=record(candidate),
                                     runner=record(Path(__file__)), exporter=record(ROOT / 'tools/SelectedExport.java'),
                                     note='candidate executable and all inputs are copied before use; source hashes identify accompanying source, not a build attestation')
        for job in JOBS:
            print(job['name'] + ': starting bounded serial reference', flush=True)
            job_output = output / job['name']
            job_output.mkdir()
            source = PORT / job['relative']
            if digest(source) != job['sha256']:
                raise ValueError(job['name'] + ': original tested binary changed')
            binary = job_output / source.name
            shutil.copy2(source, binary)
            frozen.append(record(binary))
            row = dict(name=job['name'], input=record(binary), source_input=record(source),
                       requested_functions=job['functions'], comparisons=[])
            summary['jobs'].append(row)
            stdout, _ = commands.run(job['name'] + '-inventory', [candidate, 'functions', binary], 30)
            inventory = json.loads(stdout.read_text())
            if inventory.get('status') != 'ok' or inventory.get('backend') != 'native-rust':
                raise ValueError('Rust function inventory failed')
            functions = []
            for name in job['functions']:
                selected = [function for function in inventory['functions'] if function['name'] == name]
                if len(selected) != 1:
                    raise ValueError(f'{name}: expected exactly one Rust ELF function')
                functions.append(selected[0])
                commands.run(job['name'] + '-' + name,
                             [candidate, 'decompile', binary, '--function', name, '--output',
                              job_output / ('rust-' + name)], 30)
            specs = job_output / 'specs.json'
            write_json(specs, [dict(label=f['name'], image_offset_hex=f['address_hex'],
                                    size=f['size'], set_body_to_requested_extent=True) for f in functions])
            projects = job_output / 'project'
            projects.mkdir()
            ghidra_output = job_output / 'ghidra'
            stdout, stderr = commands.run(job['name'] + '-ghidra',
                [WRAPPER, 'headless', projects, 'reference', '-import', binary,
                 '-noanalysis', '-max-cpu', '1', '-scriptPath', scripts,
                 '-postScript', 'SelectedExport.java', specs, ghidra_output, '45'], 360)
            report, targets = validate_export(job_output, job, stdout, stderr)
            row['selected_report'] = str(ghidra_output / 'selected.json')
            row['image_base'] = report['image_base']
            row['ghidra_status'] = 'complete_selected_export'
            row['function_extent_policy'] = 'trusted ELF symbol extent set only in fresh import'
            for function, target in zip(functions, targets):
                row['comparisons'].append(instruction_comparison(job_output, binary, function,
                    job_output / ('rust-' + function['name']), report, target))
            row['status'] = 'matched'
            write_json(output / 'results.json', summary)
            print(job['name'] + ': exact reachable instruction/control-flow match', flush=True)
        for item in frozen:
            if digest(Path(item['path'])) != item['sha256']:
                raise ValueError('frozen artifact changed during reference run: ' + item['path'])
        summary['frozen_artifacts'] = frozen
        summary['counts'] = dict(jobs=len(summary['jobs']), functions=sum(len(j['comparisons']) for j in summary['jobs']),
                                rust_reachable_instructions=sum(c['rust_reachable_instruction_count'] for j in summary['jobs'] for c in j['comparisons']))
        summary['status'] = 'passed'
    except Exception as error:
        summary['errors'].append(type(error).__name__ + ': ' + str(error))
    summary['commands'] = len(commands.rows)
    write_json(output / 'results.json', summary)
    print(json.dumps(dict(status=summary['status'], results=str(output / 'results.json'),
                          counts=summary.get('counts'), errors=summary['errors']), indent=2), flush=True)
    return 0 if summary['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
