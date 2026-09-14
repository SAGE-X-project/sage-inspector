"""Recompute the diagnostic verdict from preserved process exits and raw logs."""
import hashlib
import re
from pathlib import Path
from integrate_evidence import decode, require, same
from inspect_close_race import evaluate

ROOT = Path(__file__).resolve().parents[1]
BASE = 'docs/evidence/deployment/close-race/'


def validate(report, logs):
    require(report['schema_version'] == 1 and report['protocol_version'] == '0.10.0' and report['conformance'] == 'NOT_ESTABLISHED', 'diagnostic identity')
    require(report['environment'] and report['created'] and re.fullmatch('[0-9a-f]{64}', report['executable_sha256']), 'missing execution identity')
    require('\tbuild\t-race=true' in report['go_build_info'], 'race detector missing')
    require(same(report['environment_controls'], dict(GORACE='halt_on_error=0 exitcode=66', GOMAXPROCS='8')), 'execution control drift')
    require(len(report['runs']) == 2, 'missing process run')
    statuses = []
    for run, mode in zip(report['runs'], ('control', 'race')):
        require(run['mode'] == mode and type(run['timed_out']) is bool and (type(run['returncode']) is int or run['timed_out'] and run['returncode'] is None), 'invalid process identity')
        result = evaluate(logs[mode+'.stdout'], logs[mode+'.stderr'], run['returncode'], run['timed_out'], mode)
        require(same(run, dict(mode=mode, returncode=run['returncode'], timed_out=run['timed_out'], **result)), 'false process verdict')
        statuses.append(result['status'])
    status = 'FAIL' if 'FAIL' in statuses else 'INCOMPLETE' if 'INCOMPLETE' in statuses else 'PASS'
    require(report['go_status'] == status and report['rust_status'] == 'UNSUPPORTED' and report['rust_reason'] == 'close(&mut self) requires exclusive ownership; manager removal does not close retained Arc handles', 'false API support/verdict')
    return dict(report=BASE+'report.json', go_status=status, rust_status='UNSUPPORTED', conformance='NOT_ESTABLISHED')


def check(root=ROOT):
    provenance = decode((root/(BASE+'provenance.json')).read_bytes())
    expected = {BASE+p for p in ('report.json','control.stdout','control.stderr','race.stdout','race.stderr')}
    expected.add('docs/evidence/core-source-lock.json')
    require(set(provenance['files']) == expected, 'diagnostic inventory')
    for name, digest in provenance['files'].items():
        require(hashlib.sha256((root/name).read_bytes()).hexdigest() == digest, 'diagnostic evidence drift: '+name)
    report = decode((root/(BASE+'report.json')).read_bytes())
    revisions = {c['repository']:c['revision'] for c in decode((root/'docs/evidence/core-source-lock.json').read_bytes())['cores']}
    require(same(report['core_revisions'], revisions), 'diagnostic core revision drift')
    logs = {name:(root/(BASE+name)).read_text() for name in ('control.stdout','control.stderr','race.stdout','race.stderr')}
    return validate(report, logs)

if __name__ == '__main__':
    print(check())
