"""Observe pinned Go and Rust web Registry write policy checks with local fixtures."""

import argparse
import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile

from current_spec_catalog import ROOT, require, sha
from reconciled_spec_catalog import REVISION
from reconciled_spec_reg08_media import check
from observe_reconciled_reg08_record_shape import revision
from observe_reconciled_reg08_transition_shape import (
    build, envelope, PROOFS, PROOFS_SHA256, RUST_LOCK, RUST_LOCK_SHA256,
)


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-write-admission.json'
VECTOR_SHA256 = '9317f6203686cf01bc8d1bc7c09ad37325f8973c900d801ef1aeca7d07277248'
GO_REVISION = '90253ff12be0b662ef2ec18728d46d0b77340c00'
RUST_REVISION = 'fee93aabed3b126270b6e2b857ace2d1bb59a093'
EXPECTED = {
    'controller-create': 'TRANSITION_ACCEPT',
    'other-create': 'WRITE_REJECTED',
    'missing-create-credentials': 'WRITE_REJECTED',
    'empty-actor': 'WRITE_REJECTED',
    'controller-activate': 'TRANSITION_ACCEPT',
    'delegated-activate': 'TRANSITION_ACCEPT',
    'wrong-scope': 'WRITE_REJECTED',
    'wrong-expected-version': 'RECORD_STALE',
    'invalid-candidate-version': 'RECORD_INVALID',
    'controller-substitution': 'RECORD_INVALID',
    'missing-mutation-credentials': 'WRITE_REJECTED',
}


def materialize(base, mode):
    created = copy.deepcopy(base)
    created['state'] = 'created'
    created['version'] = '1'
    active = copy.deepcopy(created)
    active['state'] = 'active'
    active['version'] = '2'
    case = {
        'action': 'admission-transition', 'previous': created,
        'candidate': active, 'operation': 'activate', 'expected_version': '1',
        'actor': 'operator', 'scope': '', 'authenticated': True,
    }
    if mode in {'controller-create', 'other-create',
                'missing-create-credentials', 'empty-actor'}:
        case['action'] = 'admission-create'
        case['previous'] = None
        case['candidate'] = created
    if mode in {'other-create', 'delegated-activate', 'wrong-scope'}:
        case['actor'] = 'assistant'
    if mode == 'delegated-activate':
        case['scope'] = 'activate'
    elif mode == 'wrong-scope':
        case['scope'] = 'update-services'
    elif mode == 'wrong-expected-version':
        case['expected_version'] = '2'
    elif mode == 'invalid-candidate-version':
        case['candidate']['version'] = '3'
    elif mode == 'controller-substitution':
        case['candidate']['controller'] = 'other-operator'
    elif mode in {'missing-create-credentials', 'missing-mutation-credentials'}:
        case['authenticated'] = False
    elif mode == 'empty-actor':
        case['actor'] = ''
    elif mode not in {'controller-create', 'other-create',
                      'controller-activate', 'delegated-activate'}:
        raise ValueError('unknown admission mode: ' + mode)
    return case


def request(base, row):
    case = materialize(base['body']['record'], row['mode'])
    encode = lambda value: base64.urlsafe_b64encode(envelope(value)).rstrip(b'=').decode()
    payload = {
        'action': case['action'], 'did': base['expected_did'],
        'previous': '' if case['previous'] is None else encode(case['previous']),
        'candidate': encode(case['candidate']), 'candidate_now': base['now'],
        'operation': case['operation'], 'expected_version': case['expected_version'],
        'fixture_actor': case['actor'], 'fixture_scope': case['scope'],
        'fixture_authenticated': case['authenticated'],
    }
    encoded = json.dumps(payload, separators=(',', ':'))
    require(len(encoded.encode()) <= 150000, 'admission request bound')
    return encoded


def run_case(binary, base, row):
    process = subprocess.run([str(binary)], input=request(base, row), text=True,
                             capture_output=True, timeout=10, check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'admission adapter failed: ' + row['id'])
    result = json.loads(process.stdout)
    require(type(result) is dict and set(result) == {'verdict'} and
            result['verdict'] in set(EXPECTED.values()),
            'admission adapter verdict: ' + row['id'])
    return result['verdict']


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 admission fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'proof_fixture', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-write-admission-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            suite['proof_fixture'] == 'reg08-record-proofs.json:base' and
            len(suite['cases']) == len(EXPECTED), 'admission suite identity')
    seen = set()
    for row in suite['cases']:
        require(set(row) == {'id', 'mode', 'expected'} and
                row['mode'] in EXPECTED and row['mode'] not in seen and
                row['expected'] == EXPECTED[row['mode']],
                'admission case fields')
        seen.add(row['mode'])
    require(seen == set(EXPECTED), 'admission case set')
    proof_raw = (root / PROOFS).read_bytes()
    require(sha(proof_raw) == PROOFS_SHA256, 'proof fixture changed')
    base = json.loads(proof_raw)['base']
    require(base['now'] == 100, 'proof fixture timestamp')
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    actual_revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(actual_revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-admission-') as temporary:
        binaries = build(go_root, rust_root, Path(temporary), lock_source)
        subjects = {}
        for name, binary in binaries.items():
            cases = []
            for row in suite['cases']:
                actual = run_case(binary, base, row)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual, 'match': actual == row['expected']})
            subjects[name] = {
                'source_revision': actual_revisions[name],
                'executable_sha256': sha(binary.read_bytes()),
                'matched': sum(case['match'] for case in cases),
                'total': len(cases), 'cases': cases,
            }
    require(all(item['matched'] == len(EXPECTED) for item in subjects.values()),
            'core admission mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-write-admission-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'fixture_authority_policy': 'BOUNDED',
        'credential_authentication': 'NOT_RUN',
        'delegation_state_provenance': 'NOT_RUN',
        'atomic_write': 'NOT_RUN',
        'authenticated_source_history': 'NOT_RUN',
        'conformance': 'NOT_ESTABLISHED',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path, required=True)
    parser.add_argument('--rust-root', type=Path, required=True)
    parser.add_argument('--spec-root', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = observe(args.go_root, args.rust_root, args.spec_root)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, IndexError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        parser.exit(1, 'REG-08 admission observation FAIL: ' + str(error) + '\n')
    print('REG-08 fixture authority policy: Go 11/11, Rust 11/11; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
