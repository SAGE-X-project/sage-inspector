"""Run actual core Guard primitives; preserve unsupported mapping and lifecycle gaps."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

from inspect_guard import validate_report
from test_record010_adapters import PINS

ROOT = Path(__file__).resolve().parents[1]


def validate(summary, primitive, raw):
    validate_report(raw, primitive)
    if summary['status'] != 'INCOMPLETE' or summary['primitive_counts'] != {
            'PASS': 86, 'FAIL': 0, 'UNSUPPORTED': 16, 'NOT_RUN': 0}:
        raise ValueError('unexpected Guard support or verdict')
    for item in primitive['results']:
        expected = 'UNSUPPORTED' if item['operation'] == 'sage.guard.mcp.result' else 'PASS'
        if item['status'] != expected:
            raise ValueError('operation support mismatch')
    scenarios = summary['scenarios']
    if len(scenarios) != 37 or sum(s['steps'] for s in scenarios) != 297:
        raise ValueError('lifecycle membership mismatch')
    if any(s['status'] != 'NOT_RUN' for s in scenarios) or summary['state_subject'] is not None:
        raise ValueError('primitive execution promoted lifecycle evidence')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('go', 'rust', 'runner', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.is_relative_to(ROOT / 'docs/evidence'):
        parser.error('fresh output must not overwrite historical evidence')
    out.mkdir(parents=True, exist_ok=False)
    report = dict(kind='guard-primitive-bindings', status='RUNNING',
                  conformance='NOT_ESTABLISHED', platform=platform.platform(),
                  inspector_revision=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  subjects={}, scope='Primitive cryptography and trusted test seams; no actual registry Source, MCP mapping, durable call consumption, dispatch or host isolation.')
    try:
        raw = (ROOT / 'vectors/0.10.0/guard-records.json').read_bytes()
        report['fixture_sha256'] = hashlib.sha256(raw).hexdigest()
        report['runner_sha256'] = hashlib.sha256(args.runner.read_bytes()).hexdigest()
        for name, revision in PINS.items():
            adapter = getattr(args, name).resolve(strict=True)
            dest = out / name
            process = subprocess.run([
                sys.executable, str(ROOT / 'scripts/inspect_guard.py'), '--runner', str(args.runner.resolve()),
                '--adapter', str(adapter), '--subject', name, '--revision', revision, '--output-dir', str(dest)],
                capture_output=True, text=True, timeout=180)
            if process.returncode != 3:
                raise ValueError(f'{name}: expected INCOMPLETE, got {process.returncode}: {process.stdout} {process.stderr}')
            summary = json.loads((dest / 'summary.json').read_text())
            primitive = json.loads((dest / 'guard-records.json').read_text())
            validate(summary, primitive, raw)
            report['subjects'][name] = dict(revision=revision, adapter_sha256=hashlib.sha256(adapter.read_bytes()).hexdigest(),
                                           counts=summary['primitive_counts'], lifecycle='NOT_RUN',
                                           summary_sha256=hashlib.sha256((dest / 'summary.json').read_bytes()).hexdigest())
        report['status'] = 'PASS'
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        report.update(status='FAIL', error=str(error))
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
