#!/usr/bin/env python3
"""Summarize actual export status and warnings without treating C as source truth."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
rows = []
for directory in sorted((ROOT / 'exports').iterdir()):
    path = directory / 'selected.json'
    if not path.exists():
        continue
    report = json.loads(path.read_text())
    run_path = directory / 'run.json'
    run = json.loads(run_path.read_text()) if run_path.exists() else {}
    row = dict(job=directory.name, program=report['program'],
        executable_sha256=report.get('executable_sha256'), image_base=report['image_base'],
        language=report['language'], compiler_spec=report['compiler_spec'],
        export_complete=report.get('export_complete', False),
        selected_only=True, whole_program_analysis=False,
        process_exit_code=run.get('exit_code'), truncated=report.get('truncated'),
        analysis_timed_out=report.get('analysis_timed_out'), targets=[])
    log = (directory / 'headless.log').read_text(errors='replace')
    row['headless_warning_lines'] = [line for line in log.splitlines() if line.startswith(('WARN ', 'ERROR '))]
    for target in report['targets']:
        item = {k: target.get(k) for k in ('label', 'address', 'status', 'prototype',
            'signature_source', 'calling_convention', 'body_matches_requested_extent',
            'existing_function_body_preserved', 'existing_body_mutated', 'instruction_count',
            'raw_pcode_count', 'decompile_timed_out', 'decompile_cancelled', 'decompile_error',
            'instruction_crosses_requested_end', 'bytes_without_instructions')}
        c = target.get('c', '')
        item['c_warnings'] = re.findall(r'/\*\s*WARNING:.*?\*/', c, flags=re.S)
        item['artifact_directory'] = str(directory)
        row['targets'].append(item)
    rows.append(row)
result = dict(scope='Selected functions only; pseudocode emission is not semantic completeness or a benchmark',
    jobs=rows, selected_function_count=sum(len(r['targets']) for r in rows),
    emitted_function_count=sum(t['status']=='decompiled' for r in rows for t in r['targets']),
    complete_export_count=sum(r['export_complete'] for r in rows))
(ROOT / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k != 'jobs'}, indent=2))
