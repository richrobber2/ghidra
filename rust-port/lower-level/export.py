#!/usr/bin/env python3
"""Reproduce selected exports serially, without whole-program autoanalysis."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from localenv import DECOMPILE_ENGINE, GHIDRA_AGENT  # noqa: E402

WRAPPER = str(GHIDRA_AGENT / 'ghidra-agent')


def jobs():
    symbols = json.loads((ROOT / 'rust/symbols.json').read_text())
    result = []
    for artifact in symbols['artifacts']:
        if artifact['variant'] not in ('rust-release', 'rust-max'):
            continue
        result.append(dict(name=artifact['variant'], binary=artifact['path'],
            sha256=artifact['sha256'], specs=[dict(label=s['demangled'],
            image_offset_hex=s['address'], size=s['size_bytes'], set_body_to_requested_extent=True)
            for s in artifact['symbols']]))
    for method in json.loads((ROOT / 'java/methods.json').read_text())['methods']:
        if method['tier'] != 'c2':
            continue
        entry = int(method['verified_entry'], 16)
        result.append(dict(name='java-c2-' + method['compile_id'], binary=method['raw_file'],
            sha256=method['sha256'], base=method['main_code_begin'],
            specs=[dict(label=method['method'], address_hex=hex(entry),
            size=int(method['main_code_end'], 16) - entry, set_body_to_requested_extent=True)]))
    engine = str(DECOMPILE_ENGINE)
    result.append(dict(name='native-engine', binary=engine,
        sha256='876c28d48c07126e5db94946c10719eeb96b057c9271daa0114df34e598f262a',
        specs=[dict(label='ghidra_Action_perform', image_offset_hex='0x1f2850', size=0x139,
                    set_body_to_requested_extent=True),
               dict(label='ghidra_ActionPool_processOp', image_offset_hex='0x1f2d20', size=0x165,
                    set_body_to_requested_extent=True)]))
    for variant, offset in [('rust-release', '0x127a60'), ('rust-debug', '0x1287d0')]:
        result.append(dict(name='retained-' + variant,
            project='/workspace/ghidra-profiler/results/corpus-verified/' + variant + '/project',
            program='librust_optimization_lab.so',
            specs=[dict(label='gimli_Unit_new', address_hex=offset, size=9163)]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--select', nargs='*', help='Run only these job names')
    parser.add_argument('--rerun', action='store_true', help='Replace existing targeted exports')
    args = parser.parse_args()
    all_jobs = jobs()
    if args.select and set(args.select) - {j['name'] for j in all_jobs}:
        parser.error('Unknown selected job')
    for job in all_jobs:
        name = job['name']
        if args.select and name not in args.select:
            continue
        output = ROOT / 'exports' / name
        output.mkdir(parents=True, exist_ok=True)
        if (output / 'run.json').exists() and not args.rerun:
            print(name + ': already exported; use --rerun explicitly', flush=True)
            continue
        specs = output / 'specs.json'
        specs.write_text(json.dumps(job['specs'], indent=2) + '\n')
        if 'binary' in job:
            digest = hashlib.sha256(Path(job['binary']).read_bytes()).hexdigest()
            if digest != job['sha256']:
                raise RuntimeError(name + ': binary does not match recorded SHA256')
            projects = ROOT / 'projects'
            projects.mkdir(exist_ok=True)
            command = [WRAPPER, 'headless', str(projects), name, '-import', job['binary'], '-overwrite']
            if 'base' in job:
                command += ['-loader', 'BinaryLoader', '-loader-baseAddr', job['base'],
                            '-processor', 'x86:LE:64:default']
        else:
            command = [WRAPPER, 'headless', job['project'], 'profile', '-process', job['program'], '-readOnly']
        command += ['-noanalysis', '-scriptPath', str(ROOT / 'tools'), '-postScript',
                    'SelectedExport.java', str(specs), str(output), '45']
        started = time.monotonic()
        print(name + ': starting', flush=True)
        record = dict(job=job, command=command,
            exporter_sha256=hashlib.sha256((ROOT / 'tools/SelectedExport.java').read_bytes()).hexdigest(),
            note='Export timings are diagnostic, not benchmark samples; exported C can contain unresolved flow/type warnings')
        with (output / 'headless.log').open('w') as log:
            try:
                record['exit_code'] = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=360).returncode
            except subprocess.TimeoutExpired:
                record['exit_code'] = None
                record['process_timeout'] = True
        record['elapsed_seconds'] = time.monotonic() - started
        report_path = output / 'selected.json'
        report = json.loads(report_path.read_text()) if report_path.exists() else {}
        record['valid_complete_export'] = bool(record['exit_code'] == 0 and report.get('export_complete') and
            not report.get('truncated') and not report.get('analysis_timed_out') and
            report.get('decompiled_count') == len(job['specs']))
        record['target_statuses'] = [t.get('status') for t in report.get('targets', [])]
        record['target_decompiler_messages'] = [t.get('decompile_error') for t in report.get('targets', [])]
        record['export_footer_present'] = 'SELECTED_EXPORT_OK ' + str(report_path) in (output / 'headless.log').read_text(errors='replace')
        record['valid_complete_export'] = record['valid_complete_export'] and record['export_footer_present']
        (output / 'run.json').write_text(json.dumps(record, indent=2) + '\n')
        print(name + ': ' + str(record['valid_complete_export']) + ' ' + str(record['target_statuses']), flush=True)


if __name__ == '__main__':
    main()
