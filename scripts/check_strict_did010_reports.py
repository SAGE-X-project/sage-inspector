"""Check exact-revision Go/Rust parser reports without promoting ID cases."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / 'vectors/0.10.0/strict-did010.json'
SUITE_SHA256 = '42bce21df8d10ac3ebe9ecb790bd398997813a471cec7d9e66eee3c80a65daef'
SPEC_REVISION = 'fa006fd917ad365eb554a27f4178301cd66e2379'
CASE_IDS = (
    'canonical-web', 'canonical-alabel', 'canonical-chain',
    'uppercase-scheme', 'uppercase-method', 'uppercase-domain', 'ip-literal',
    'trailing-domain-dot', 'missing-agent', 'extra-segment', 'legacy-alias',
    'reserved-kind', 'chain-leading-zero', 'uppercase-address', 'long-agent',
    'canonical-key-url', 'key-url-no-fragment', 'key-url-extra-fragment',
    'key-url-invalid-fragment', 'key-url-uppercase-prefix',
)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def suite():
    raw = SUITE.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SUITE_SHA256, 'suite bytes changed')
    value = json.loads(raw)
    require(value['schema_version'] == 1 and value['protocol_version'] == '0.10.0'
            and value['profile'] == 'primitive-foundation'
            and value['id'] == 'sage-strict-did-0.10.0'
            and SPEC_REVISION in value['sources'][0]['reference']
            and tuple(case['id'] for case in value['cases']) == CASE_IDS,
            'suite identity changed')
    return value


def assess(name, report, cases, revision, executable=None):
    subject = report['subject']
    require(report['schema_version'] == 1 and report['protocol_version'] == '0.10.0'
            and report['profile'] == 'primitive-foundation'
            and report['suite_id'] == 'sage-strict-did-0.10.0'
            and report['suite_sha256'] == SUITE_SHA256
            and report['sources'] == suite()['sources']
            and report['scope'] == ('Only listed primitive cases; no full SAGE, '
                                    'state-machine, registry or Execution Guard certification.')
            and subject['kind'] == 'external' and subject['revision'] == revision
            and re.fullmatch('[0-9a-f]{64}', subject['executable_sha256']) is not None
            and report['status'] == 'PASS'
            and report['counts'] == {'PASS': len(cases), 'FAIL': 0,
                                     'UNSUPPORTED': 0, 'NOT_RUN': 0}
            and len(report['results']) == len(cases), name + ' report identity')
    if executable is not None:
        require(subject['executable_sha256'] == hashlib.sha256(executable.read_bytes()).hexdigest(),
                name + ' executable hash')
    for case, result in zip(cases, report['results']):
        require(result['case_id'] == case['id']
                and result['operation'] == case['operation']
                and result['rule_ids'] == case['rule_ids']
                and result['source_ids'] == case['source_ids']
                and result['expected'] == case['expected']
                and result['status'] == 'PASS'
                and result['actual']['schema_version'] == 1
                and result['actual']['case_id'] == case['id']
                and result['actual']['verdict'] == case['expected']['verdict']
                and result['actual']['output'] == case['expected']['output'],
                name + ' case ' + case['id'])


def pinned_revision(root, revision):
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root,
                                     text=True).strip()
    require(actual == revision and
            not subprocess.check_output(['git', 'diff', 'HEAD', '--'], cwd=root),
            'source revision or working tree changed')


def check(go_root, rust_root, spec_root, go_adapter, rust_adapter, go_report, rust_report,
          go_revision, rust_revision):
    expected = suite()
    for root, revision in ((go_root, go_revision), (rust_root, rust_revision),
                           (spec_root, SPEC_REVISION)):
        pinned_revision(root, revision)
    assess('go', json.loads(go_report.read_bytes()), expected['cases'], go_revision, go_adapter)
    assess('rust', json.loads(rust_report.read_bytes()), expected['cases'], rust_revision,
           rust_adapter)
    return {'go': {'PASS': len(CASE_IDS)}, 'rust': {'PASS': len(CASE_IDS)},
            'conformance': 'NOT_ESTABLISHED'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('go-root', 'rust-root', 'spec-root', 'go-adapter', 'rust-adapter',
                 'go-report', 'rust-report',
                 'go-revision', 'rust-revision'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    print(json.dumps(check(Path(args.go_root), Path(args.rust_root), Path(args.spec_root),
                           Path(args.go_adapter), Path(args.rust_adapter),
                           Path(args.go_report), Path(args.rust_report),
                           args.go_revision, args.rust_revision), sort_keys=True))
