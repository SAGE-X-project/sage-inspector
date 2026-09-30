"""Observe pinned Go and Rust Registry transaction decisions with local fixtures."""

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


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-transaction-boundary.json'
VECTOR_SHA256 = '7ea4d859c6db5fb01afd89e94ac200267c47cdc267100a4a1f7e7a955a8d9220'
GO_REVISION = '6d6c29e927a83895aaf0cc8334291551c7ce8d3d'
RUST_REVISION = '0ae1c6f67ea68ea79e6bdf38da7cba793bd778bb'
EXPECTED = {
    'create': ('TRANSITION_ACCEPT', True, 1, False),
    'activate': ('TRANSITION_ACCEPT', True, 2, False),
    'stale-version': ('RECORD_STALE', False, 1, False),
    'wrong-source': ('RECORD_UNREACHABLE', False, 0, False),
    'missing-credentials': ('WRITE_REJECTED', False, 1, False),
    'missing-history': ('RECORD_INVALID', False, 0, False),
    'deactivate': ('TRANSITION_ACCEPT', True, 3, True),
    'terminal-reuse': ('RECORD_INVALID', False, 3, True),
    'tombstone-mismatch': ('RECORD_INVALID', False, 2, True),
    'expired-key-recovery': ('TRANSITION_ACCEPT', True, 3, False),
    'duplicate-create': ('RECORD_INVALID', False, 1, False),
    'delegated-activate': ('TRANSITION_ACCEPT', True, 2, False),
    'wrong-delegation': ('WRITE_REJECTED', False, 1, False),
}


def expectation(mode):
    verdict, committed, history_len, tombstoned = EXPECTED[mode]
    return {'verdict': verdict, 'committed': committed,
            'history_len': history_len, 'tombstoned': tombstoned}


def materialize(base, mode):
    created = copy.deepcopy(base)
    created['state'] = 'created'
    created['version'] = '1'
    active = copy.deepcopy(created)
    active['state'] = 'active'
    active['version'] = '2'
    terminal = copy.deepcopy(active)
    terminal['state'] = 'deactivated'
    terminal['version'] = '3'
    history = [
        {'record': created, 'at': 100, 'operation': 'create'},
    ]
    case = {
        'previous': created, 'candidate': active, 'history': history,
        'operation': 'activate', 'expected_version': '1', 'now': 100,
        'actor': 'operator', 'scope': '', 'authenticated': True,
        'source': 'trusted-web-origin', 'tombstoned': False,
    }
    if mode in {'create', 'wrong-source'}:
        case.update(previous=None, candidate=created, history=[],
                    operation='create', expected_version='')
        if mode == 'wrong-source':
            case['source'] = 'other-origin'
    elif mode == 'stale-version':
        case['expected_version'] = '2'
    elif mode == 'missing-credentials':
        case['authenticated'] = False
    elif mode == 'missing-history':
        case['history'] = []
    elif mode in {'deactivate', 'terminal-reuse', 'tombstone-mismatch'}:
        case['history'] = history + [
            {'record': active, 'at': 100, 'operation': 'activate'},
        ]
        case.update(previous=active, candidate=terminal,
                    operation='deactivate', expected_version='2')
        if mode == 'terminal-reuse':
            case['history'].append(
                {'record': terminal, 'at': 100, 'operation': 'deactivate'})
            case.update(previous=terminal, candidate=created,
                        operation='create', expected_version='', tombstoned=True)
        elif mode == 'tombstone-mismatch':
            case['tombstoned'] = True
    elif mode == 'expired-key-recovery':
        created['keys'] = created['keys'][:2]
        created['keys'][0]['expires'] = 101
        active = copy.deepcopy(created)
        active['state'] = 'active'
        active['version'] = '2'
        repaired = copy.deepcopy(active)
        repaired['version'] = '3'
        repaired['keys'].append(copy.deepcopy(base['keys'][2]))
        case.update(previous=active, candidate=repaired, now=102,
                    operation='add-key', expected_version='2', history=[
                        {'record': created, 'at': 100, 'operation': 'create'},
                        {'record': active, 'at': 100, 'operation': 'activate'},
                    ])
    elif mode == 'duplicate-create':
        case.update(candidate=created, operation='create', expected_version='')
    elif mode in {'delegated-activate', 'wrong-delegation'}:
        case['actor'] = 'assistant'
        case['scope'] = 'activate' if mode == 'delegated-activate' else 'update-services'
    elif mode != 'activate':
        raise ValueError('unknown transaction mode: ' + mode)
    return case


def request(base, row):
    case = materialize(base['body']['record'], row['mode'])
    encode = lambda record: base64.urlsafe_b64encode(envelope(record)).rstrip(b'=').decode()
    payload = {
        'action': 'transaction', 'did': base['expected_did'],
        'previous': '' if case['previous'] is None else encode(case['previous']),
        'candidate': encode(case['candidate']), 'candidate_now': case['now'],
        'operation': case['operation'], 'expected_version': case['expected_version'],
        'fixture_actor': case['actor'], 'fixture_scope': case['scope'],
        'fixture_authenticated': case['authenticated'],
        'fixture_source': case['source'], 'trusted_source': 'trusted-web-origin',
        'fixture_tombstoned': case['tombstoned'],
        'history': [{'envelope': encode(entry['record']), 'at': entry['at'],
                     'operation': entry['operation']} for entry in case['history']],
    }
    encoded = json.dumps(payload, separators=(',', ':'))
    require(len(encoded.encode()) <= 150000, 'transaction request bound')
    return encoded


def run_case(binary, base, row):
    process = subprocess.run([str(binary)], input=request(base, row), text=True,
                             capture_output=True, timeout=10, check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'transaction adapter failed: ' + row['id'])
    actual = json.loads(process.stdout)
    require(type(actual) is dict and set(actual) == set(expectation(row['mode'])) and
            type(actual['committed']) is bool and
            type(actual['history_len']) is int and
            type(actual['tombstoned']) is bool and
            type(actual['verdict']) is str,
            'transaction adapter result: ' + row['id'])
    return actual


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 transaction fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'proof_fixture', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-transaction-boundary-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            suite['proof_fixture'] == 'reg08-record-proofs.json:base' and
            len(suite['cases']) == len(EXPECTED), 'transaction suite identity')
    seen = set()
    for row in suite['cases']:
        require(set(row) == {'id', 'mode', 'expected'} and
                row['mode'] in EXPECTED and row['mode'] not in seen and
                row['expected'] == expectation(row['mode']),
                'transaction case fields')
        seen.add(row['mode'])
    require(seen == set(EXPECTED), 'transaction case set')
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
    with tempfile.TemporaryDirectory(prefix='sage-reg08-transaction-') as temporary:
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
            'core transaction mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-transaction-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'transaction_decision': 'BOUNDED',
        'authenticated_source_history': 'NOT_RUN',
        'credential_authentication': 'NOT_RUN',
        'delegation_state_provenance': 'NOT_RUN',
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
        parser.exit(1, 'REG-08 transaction observation FAIL: ' + str(error) + '\n')
    print('REG-08 transaction decision: Go 13/13, Rust 13/13; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
