#!/usr/bin/env python3
"""Snapshot and export three exact release-CLI symbols; fresh results only."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent
COMPONENT = ROOT.parent
PARENT = COMPONENT.parent
sys.path.insert(0, str(PARENT))
from localenv import DECOMPILE_ENGINE, GHIDRA_AGENT  # noqa: E402

WRAPPER = GHIDRA_AGENT / 'ghidra-agent'
EXPORTER = PARENT / 'lower-level/tools/SelectedExport.java'
ENGINE = DECOMPILE_ENGINE
ORIGINAL_ENGINE_SHA256 = '876c28d48c07126e5db94946c10719eeb96b057c9271daa0114df34e598f262a'
TARGETS = {
    'parse_program_headers': ('ghidra_elf_segments::parse_program_headers',),
    'raw': ('<ghidra_elf_segments::ProgramHeaders>::raw', 'ghidra_elf_segments::ProgramHeaders::raw'),
    'next': ('<ghidra_elf_segments::ProgramHeaderIter as core::iter::traits::iterator::Iterator>::next',),
}
SOURCES = [
    COMPONENT / 'Cargo.toml', COMPONENT / 'Cargo.lock',
    COMPONENT / 'src/lib.rs', COMPONENT / 'src/main.rs',
    PARENT / 'Cargo.toml', PARENT / 'src/lib.rs',
    EXPORTER, WRAPPER, GHIDRA_AGENT / 'cli.py', ROOT / 'run.py',
]


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def invoke(command, directory, stem, records, timeout=30):
    """Retain stdout/stderr and kill the complete command group on timeout."""
    record = {'command': [str(item) for item in command], 'timeout_seconds': timeout,
              'stdout': stem + '.stdout.txt', 'stderr': stem + '.stderr.txt',
              'process_timeout': False}
    records.append(record)
    started = time.monotonic()
    with (directory / record['stdout']).open('wb') as out, (directory / record['stderr']).open('wb') as err:
        process = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
        try:
            record['exit_code'] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record['process_timeout'] = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            record['exit_code'] = process.returncode
    record['elapsed_seconds'] = time.monotonic() - started
    save(directory / 'commands.json', records)
    if record['exit_code'] != 0 or record['process_timeout']:
        raise RuntimeError(f'{stem}: command failed or timed out; retained logs identify the failure')
    return (directory / record['stdout']).read_text(errors='replace')


def symbols(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([tT])\s+(.+)', line)
        if not match:
            continue
        address, size, kind, name = match.groups()
        canonical = re.sub(r'::h[0-9a-f]{16}$', '', name)
        for label, spellings in TARGETS.items():
            if canonical in spellings:
                if label in result:
                    raise RuntimeError(f'Ambiguous matching symbol: {label}')
                size = int(size, 16)
                if not 0 < size <= 65536:
                    raise RuntimeError(f'{label}: expected 1..65536-byte function extent')
                result[label] = {'label': label, 'demangled': name, 'type': kind,
                                 'address_hex': hex(int(address, 16)), 'size_bytes': size}
    missing = set(TARGETS) - result.keys()
    if missing:
        raise RuntimeError('Required standalone symbols absent (possibly inlined): ' + ', '.join(sorted(missing)))
    return [result[label] for label in TARGETS]


def validate_report(report, report_path, launch_log, selected_symbols, artifact_sha256):
    targets = report.get('targets', [])
    expected_labels = [entry['label'] for entry in selected_symbols]
    footer = 'SELECTED_EXPORT_OK ' + str(report_path)
    global_ok = (
        report.get('export_complete') is True
        and report.get('truncated') is False
        and report.get('cancelled') is False
        and report.get('analysis_timed_out') is False
        and report.get('selected_only') is True
        and report.get('scope_truncated') is True
        and report.get('automatic_analysis_requested_by_script') is False
        and report.get('requested_count') == len(expected_labels)
        and report.get('attempted_count') == len(expected_labels)
        and report.get('decompiled_count') == len(expected_labels)
        and report.get('failed_count') == 0
        and report.get('language') == 'x86:LE:64:default'
        and report.get('executable_sha256', '').lower() == artifact_sha256
        and launch_log.count(footer) == 1
        and [target.get('label') for target in targets] == expected_labels
    )
    rows = []
    expected = {entry['label']: entry for entry in selected_symbols}
    for target in targets:
        symbol = expected.get(target.get('label'), {})
        ok = (target.get('status') == 'decompiled'
              and target.get('decompile_timed_out') is False
              and target.get('decompile_cancelled') is False
              and target.get('decompile_failed_to_start') is False
              and target.get('instruction_export_truncated') is False
              and target.get('instruction_crosses_requested_end') is False
              and target.get('bounded_disassembly_ok') is True
              and target.get('body_matches_requested_extent') is True
              and target.get('body_outside_requested_extent') == []
              and target.get('set_body_to_requested_extent_requested') is True
              and target.get('size_bytes') == symbol.get('size_bytes')
              and target.get('spec', {}).get('image_offset_hex') == symbol.get('address_hex')
              and bool(target.get('c_file')))
        rows.append({key: target.get(key) for key in (
            'label', 'status', 'address', 'size_bytes', 'prototype', 'signature_source',
            'calling_convention', 'instruction_count', 'raw_pcode_count',
            'bytes_without_instructions', 'decompile_error', 'c_file', 'listing_file',
            'instructions_file', 'raw_pcode_file')})
        rows[-1]['valid_complete_selected_export'] = ok
        rows[-1]['complete_instruction_coverage'] = target.get('bytes_without_instructions') == []
        global_ok = global_ok and ok
    return {'valid_complete_selected_export': bool(global_ok),
            'export_footer_present_once': launch_log.count(footer) == 1,
            'complete_instruction_coverage': bool(rows) and all(row['complete_instruction_coverage'] for row in rows),
            'prototype_warning': report.get('prototype_warning'),
            'decompiler_flow_warning': report.get('decompiler_flow_warning'), 'targets': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New results directory; existing paths refused')
    parser.add_argument('--binary', type=Path, default=COMPONENT / 'target/release/ghidra-elf-segments')
    args = parser.parse_args()
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    summary = {'complete': False, 'scope': 'Three named release-CLI functions only; no automatic analysis',
               'note': 'Export times and instruction counts are not performance measurements.'}
    try:
        binary = args.binary.resolve(strict=True)
        artifact = output / 'ghidra-elf-segments'
        binary_sha256 = digest(binary)
        shutil.copyfile(binary, artifact)
        artifact.chmod(0o644)  # Imported and disassembled, never executed by this workflow.
        if digest(artifact) != binary_sha256:
            raise RuntimeError('Binary changed during snapshot')
        provenance = {'binary_source': str(binary), 'binary_sha256': binary_sha256,
                      'artifact': str(artifact), 'sources': [],
                      'engine': {'path': str(ENGINE), 'sha256': digest(ENGINE)}}
        if provenance['engine']['sha256'] != ORIGINAL_ENGINE_SHA256:
            raise RuntimeError('Installed native engine does not match the retained original SHA-256')
        source_dir = output / 'sources'
        source_dir.mkdir()
        for index, path in enumerate(SOURCES):
            source_hash = digest(path)
            copy = source_dir / f'{index:02d}-{path.name}'
            shutil.copyfile(path, copy)
            if digest(copy) != source_hash:
                raise RuntimeError(f'Source changed during snapshot: {path}')
            provenance['sources'].append({'path': str(path), 'snapshot': str(copy), 'sha256': source_hash})
        save(output / 'provenance.json', provenance)
        for tool in ['nm', 'objdump', 'readelf']:
            invoke([tool, '--version'], output, tool + '-version', commands)
        elf_header = invoke(['readelf', '-hW', str(artifact)], output, 'elf-header', commands)
        if not (re.search(r'Class:\s+ELF64', elf_header)
                and re.search(r'Type:\s+DYN', elf_header)
                and 'little endian' in elf_header
                and 'Advanced Micro Devices X86-64' in elf_header):
            raise RuntimeError('This image-relative workflow requires a little-endian x86-64 ET_DYN artifact')
        nm_text = invoke(['nm', '-S', '-C', '--defined-only', str(artifact)], output, 'nm-demangled', commands)
        selected_symbols = symbols(nm_text)
        save(output / 'symbols.json', selected_symbols)
        specs = []
        for entry in selected_symbols:
            specs.append({'label': entry['label'], 'image_offset_hex': entry['address_hex'],
                          'size': entry['size_bytes'], 'set_body_to_requested_extent': True})
            start = int(entry['address_hex'], 16)
            invoke(['objdump', '-drwC', f'--start-address={start}',
                    f'--stop-address={start + entry["size_bytes"]}', str(artifact)],
                   output, entry['label'] + '-objdump', commands)
        specs_path = output / 'specs.json'
        save(specs_path, specs)
        projects = output / 'project'
        projects.mkdir()
        exports = output / 'export'
        exports.mkdir()
        script_dir = output / 'scripts'
        script_dir.mkdir()
        shutil.copyfile(EXPORTER, script_dir / EXPORTER.name)
        if digest(script_dir / EXPORTER.name) != next(row['sha256'] for row in provenance['sources'] if row['path'] == str(EXPORTER)):
            raise RuntimeError('Exporter changed after snapshot')
        command = [str(WRAPPER), 'headless', str(projects), 'segments-selected', '-import', str(artifact),
                   '-noanalysis', '-max-cpu', '1', '-scriptPath', str(script_dir),
                   '-postScript', EXPORTER.name, str(specs_path), str(exports), '45']
        invoke(command, output, 'headless', commands, timeout=360)
        report_path = exports / 'selected.json'
        report = json.loads(report_path.read_text())
        log = (output / 'headless.stdout.txt').read_text(errors='replace') + (output / 'headless.stderr.txt').read_text(errors='replace')
        summary.update(validate_report(report, report_path, log, selected_symbols, binary_sha256))
        summary['binary_unchanged_after_export'] = digest(binary) == binary_sha256 and digest(artifact) == binary_sha256
        summary['sources_unchanged_after_export'] = all(digest(Path(row['path'])) == row['sha256'] for row in provenance['sources'])
        summary['engine_unchanged_after_export'] = digest(ENGINE) == provenance['engine']['sha256']
        summary['complete'] = (summary['valid_complete_selected_export']
                               and summary['binary_unchanged_after_export'] and summary['sources_unchanged_after_export']
                               and summary['engine_unchanged_after_export'])
        for target in summary['targets']:
            for key in ('c_file', 'listing_file', 'instructions_file', 'raw_pcode_file'):
                if not (exports / target[key]).is_file():
                    raise RuntimeError(f'Missing selected export file: {target[key]}')
            c_text = (exports / target['c_file']).read_text()
            target['c_warning_comments'] = re.findall(r'/\*\s*WARNING:.*?\*/', c_text, re.DOTALL)
        if not summary['complete']:
            raise RuntimeError('Selected export gates failed; see summary.json and retained logs')
    except Exception as error:
        summary['complete'] = False
        summary['error'] = f'{type(error).__name__}: {error}'
    save(output / 'summary.json', summary)
    print(json.dumps({'complete': summary['complete'], 'summary': str(output / 'summary.json'),
                      'error': summary.get('error')}))
    return 0 if summary['complete'] else 1


if __name__ == '__main__':
    sys.exit(main())
