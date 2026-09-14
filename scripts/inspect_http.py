"""Run the versioned HTTP inspection bundle against any schema1 subject adapter.
The runner owns subject execution and verdict comparison; this tool owns coverage
aggregation. A missing core capability never prevents preparing the Inspector.
"""
import argparse
import collections
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITES = ('http-signatures', 'http-boundaries', 'http-envelope-primitives')
STATUSES = ('PASS', 'FAIL', 'UNSUPPORTED', 'NOT_RUN')
CONDITIONAL = {'fields-32768', 'fields-32769', 'signature-value-8192',
               'signature-value-8193', 'signature-input-value-8192', 'signature-input-value-8193'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def summarize(pairs):
    """Validate complete report membership before combining trusted runner results."""
    if len(pairs) != len(SUITES):
        raise ValueError('all HTTP suites are required')
    counts = collections.Counter({status: 0 for status in STATUSES})
    rules, suites, conditional = {}, [], []
    subject = None
    seen = set()
    for suite_bytes, report in pairs:
        suite = json.loads(suite_bytes)
        if suite['id'] in seen:
            raise ValueError('duplicate suite')
        seen.add(suite['id'])
        if report['suite_id'] != suite['id'] or report['suite_sha256'] != digest(suite_bytes):
            raise ValueError('report suite identity/hash mismatch')
        if report['schema_version'] != 1 or report['protocol_version'] != '0.10.0':
            raise ValueError('report version mismatch')
        if subject is None:
            subject = report['subject']
        if report['subject'] != subject:
            raise ValueError('mixed subject revision or executable')
        expected = {case['id']: case for case in suite['cases']}
        if len(report['results']) != len(expected):
            raise ValueError('missing or extra observations')
        observed, local = set(), collections.Counter({status: 0 for status in STATUSES})
        for result in report['results']:
            ident, status = result['case_id'], result['status']
            if ident not in expected or ident in observed or status not in STATUSES:
                raise ValueError('unknown, duplicate, or invalid result')
            observed.add(ident)
            case = expected[ident]
            if result['operation'] != case['operation'] or result['expected'] != case['expected'] or result['rule_ids'] != case['rule_ids']:
                raise ValueError('result differs from frozen case')
            actual = result.get('actual')
            if status in ('PASS', 'UNSUPPORTED') and (not actual or actual.get('case_id') != ident or actual.get('schema_version') != 1):
                raise ValueError('observation identity mismatch')
            if status == 'PASS' and (not actual or actual['verdict'] != case['expected']['verdict'] or actual['output'] != case['expected']['output']):
                raise ValueError('unsupported or mismatched result promoted to PASS')
            if status == 'UNSUPPORTED' and (not actual or actual['verdict'] != 'UNSUPPORTED'):
                raise ValueError('unsupported result lacks observation')
            local[status] += 1
            ref = {'suite_id': suite['id'], 'case_id': ident, 'status': status}
            if suite['id'] == 'sage-http-boundaries-0.10.0' and ident in CONDITIONAL:
                conditional.append(ref)
            for rule in case['rule_ids']:
                rules.setdefault(rule, []).append(ref)
        inferred = 'FAIL' if local['FAIL'] else 'INCOMPLETE' if local['UNSUPPORTED'] or local['NOT_RUN'] else 'PASS'
        if dict(local) != report['counts'] or report['status'] != inferred:
            raise ValueError('report counts or conclusion mismatch')
        counts.update(local)
        suites.append({'id': suite['id'], 'sha256': digest(suite_bytes), 'status': inferred, 'counts': dict(local)})
    ids = {'sage-http-signatures-0.10.0', 'sage-http-boundaries-0.10.0', 'sage-http-envelope-primitives-0.10.0'}
    if seen != ids:
        raise ValueError('unexpected bundle membership')
    status = 'FAIL' if counts['FAIL'] else 'INCOMPLETE' if counts['UNSUPPORTED'] or counts['NOT_RUN'] or conditional else 'PASS'
    return {'schema_version': 1, 'protocol_version': '0.10.0', 'bundle': 'http-envelope-inspection',
            'subject': subject, 'status': status, 'counts': dict(counts), 'suites': suites, 'rules': rules,
            'conditional_cases': conditional,
            'condition': 'Exact field-size counting uses the declared fixture convention pending normative clarification.',
            'scope': 'Listed HTTP/envelope inspection cases only. Inspector implementation readiness is separate from subject conformance; no whole-protocol certification.',
            'follow_up': 'Reconnect unsupported operations after core implementation; retain frozen expectations and rerun the complete bundle.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', required=True, type=Path)
    parser.add_argument('--adapter', required=True, type=Path)
    parser.add_argument('--subject', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    try:
        runner, adapter = args.runner.resolve(strict=True), args.adapter.resolve(strict=True)
        output = args.output_dir.resolve()
        # Existing evidence is never overwritten. Use a new directory for every run.
        output.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        print(f'HTTP inspection configuration error: {error}')
        return 2
    pairs = []
    try:
        for name in SUITES:
            source = ROOT/'vectors/0.10.0'/f'{name}.json'
            suite_bytes = source.read_bytes()
            path = output/f'{name}.json'
            count = len(json.loads(suite_bytes)['cases'])
            result = subprocess.run([str(runner), '-suite', str(source), '-adapter', str(adapter),
                                     '-subject', args.subject, '-revision', args.revision, '-report', str(path)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=count*5+30, check=False)
            if result.returncode not in (0, 1, 3):
                raise ValueError(f'{name}: runner failed with exit {result.returncode}')
            report = json.loads(path.read_text())
            if result.returncode != {'PASS': 0, 'FAIL': 1, 'INCOMPLETE': 3}[report['status']]:
                raise ValueError('runner exit/report mismatch')
            pairs.append((suite_bytes, report))
        report = summarize(pairs)
        report['evidence_files'] = {f'{name}.json': digest((output/f'{name}.json').read_bytes()) for name in SUITES}
        (output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({'status': report['status'], 'counts': report['counts'], 'report': str(output/'summary.json')}))
        return {'PASS': 0, 'FAIL': 1, 'INCOMPLETE': 3}[report['status']]
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        (output/'summary.json').write_text(json.dumps({'status': 'ERROR', 'error': str(error)})+'\n')
        print(f'HTTP inspection failed: {error}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
