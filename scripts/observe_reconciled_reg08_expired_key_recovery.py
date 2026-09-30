"""Observe pinned Go and Rust recovery after an accepted signing key expires."""

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


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-expired-key-recovery.json'
VECTOR_SHA256 = '528cec670d9ae1da1ab5dec7847c392fee09b35f7681c1168f9a3312eab449a6'
GO_REVISION = '7f46bc8871a448f976ef7551866a466ddf1e7489'
RUST_REVISION = 'c135bccd3f1d34b3770e2e5519ccd38f0bf5475d'
EXPECTED = {
    'controller-repair': 'TRANSITION_ACCEPT',
    'delegated-repair': 'TRANSITION_ACCEPT',
    'strict-transition': 'RECORD_INVALID',
    'unrepaired-candidate': 'RECORD_INVALID',
    'revoked-prior': 'RECORD_INVALID',
    'invalid-prior-proof': 'RECORD_INVALID',
    'stale-version': 'RECORD_STALE',
    'missing-credentials': 'WRITE_REJECTED',
}


def materialize(base, mode):
    previous = copy.deepcopy(base)
    previous['state'] = 'active'
    previous['version'] = '2'
    previous['keys'] = previous['keys'][:2]
    previous['keys'][0]['expires'] = 101
    candidate = copy.deepcopy(previous)
    candidate['version'] = '3'
    candidate['keys'].append(copy.deepcopy(base['keys'][2]))
    case = {
        'action': 'admission-transition', 'previous': previous,
        'candidate': candidate, 'operation': 'add-key',
        'expected_version': '2', 'actor': 'operator', 'scope': '',
        'authenticated': True,
    }
    if mode == 'delegated-repair':
        case['actor'] = 'assistant'
        case['scope'] = 'add-key'
    elif mode == 'strict-transition':
        case['action'] = 'transition'
    elif mode == 'unrepaired-candidate':
        candidate['keys'][-1]['expires'] = 101
    elif mode == 'revoked-prior':
        previous['keys'][0]['state'] = 'revoked'
        candidate['keys'][0]['state'] = 'revoked'
    elif mode == 'invalid-prior-proof':
        previous['keys'][0]['proof']['value'] = 'invalid'
    elif mode == 'stale-version':
        case['expected_version'] = '1'
    elif mode == 'missing-credentials':
        case['authenticated'] = False
    elif mode != 'controller-repair':
        raise ValueError('unknown recovery mode: ' + mode)
    return case


def request(base, row):
    case = materialize(base['body']['record'], row['mode'])
    encode = lambda value: base64.urlsafe_b64encode(envelope(value)).rstrip(b'=').decode()
    payload = {
        'action': case['action'], 'did': base['expected_did'],
        'previous': encode(case['previous']), 'candidate': encode(case['candidate']),
        'previous_now': 102, 'candidate_now': 102,
        'operation': case['operation'], 'expected_version': case['expected_version'],
        'fixture_actor': case['actor'], 'fixture_scope': case['scope'],
        'fixture_authenticated': case['authenticated'],
    }
    encoded = json.dumps(payload, separators=(',', ':'))
    require(len(encoded.encode()) <= 150000, 'recovery request bound')
    return encoded


def run_case(binary, base, row):
    process = subprocess.run([str(binary)], input=request(base, row), text=True,
                             capture_output=True, timeout=10, check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'recovery adapter failed: ' + row['id'])
    result = json.loads(process.stdout)
    require(type(result) is dict and set(result) == {'verdict'} and
            result['verdict'] in set(EXPECTED.values()),
            'recovery adapter verdict: ' + row['id'])
    return result['verdict']


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 recovery fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'proof_fixture', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-expired-key-recovery-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            suite['proof_fixture'] == 'reg08-record-proofs.json:base' and
            len(suite['cases']) == len(EXPECTED), 'recovery suite identity')
    seen = set()
    for row in suite['cases']:
        require(set(row) == {'id', 'mode', 'expected'} and
                row['mode'] in EXPECTED and row['mode'] not in seen and
                row['expected'] == EXPECTED[row['mode']],
                'recovery case fields')
        seen.add(row['mode'])
    require(seen == set(EXPECTED), 'recovery case set')
    proof_raw = (root / PROOFS).read_bytes()
    require(sha(proof_raw) == PROOFS_SHA256, 'proof fixture changed')
    base = json.loads(proof_raw)['base']
    require(base['now'] == 100, 'proof fixture timestamp')
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-recovery-') as temporary:
        binaries = build(go_root, rust_root, Path(temporary), lock_source)
        subjects = {}
        for name, binary in binaries.items():
            cases = []
            for row in suite['cases']:
                actual = run_case(binary, base, row)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual, 'match': actual == row['expected']})
            subjects[name] = {
                'source_revision': revisions[name],
                'executable_sha256': sha(binary.read_bytes()),
                'matched': sum(case['match'] for case in cases),
                'total': len(cases), 'cases': cases,
            }
    require(all(item['matched'] == len(EXPECTED) for item in subjects.values()),
            'core recovery mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-expired-key-recovery-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'expired_key_recovery_policy': 'BOUNDED',
        'credential_authentication': 'NOT_RUN',
        'delegation_state_provenance': 'NOT_RUN',
        'authenticated_source_history': 'NOT_RUN',
        'atomic_write': 'NOT_RUN',
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
        parser.exit(1, 'REG-08 recovery observation FAIL: ' + str(error) + '\n')
    print('REG-08 expired-key recovery policy: Go 8/8, Rust 8/8; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
