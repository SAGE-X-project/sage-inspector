"""Observe local Registry journal recovery across separate adapter processes."""

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
    build, PROOFS, PROOFS_SHA256, RUST_LOCK, RUST_LOCK_SHA256,
)

VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-durable-write.json'
VECTOR_SHA256 = '91b5899f81936fffbbc0edab613deff720f90d97f5fc7502b3a541bc35ea911f'
GO_REVISION = 'ed8c12e32168c3c13ef44564c4bd52a5d28eb9fd'
RUST_REVISION = '1419499dff05e694114ac1a3470bed073f654098'
EXPECTED = {
    'create': ('TRANSITION_ACCEPT', True, 1, False),
    'wrong-source-open': None,
    'activate': ('TRANSITION_ACCEPT', True, 2, False),
    'missing-credentials': ('WRITE_REJECTED', False, 2, False),
    'stale-version': ('RECORD_STALE', False, 2, False),
    'deactivate': ('TRANSITION_ACCEPT', True, 3, True),
    'terminal-reuse': ('RECORD_INVALID', False, 3, True),
    'incomplete-restart': None,
    'expired-create': ('TRANSITION_ACCEPT', True, 1, False),
    'expired-activate': ('TRANSITION_ACCEPT', True, 2, False),
    'expired-repair': ('TRANSITION_ACCEPT', True, 3, False),
    'recovered-service-update': ('TRANSITION_ACCEPT', True, 4, False),
}
SEQUENCES = {
    'main': list(EXPECTED)[:8],
    'recovery': list(EXPECTED)[8:],
}


def expectation(mode):
    values = EXPECTED[mode]
    if values is None:
        return {'exit_code': 2}
    return dict(zip(('verdict', 'committed', 'history_len', 'tombstoned'), values))


def materialize(base, mode):
    created = copy.deepcopy(base)
    created.update(state='created', version='1')
    active = copy.deepcopy(created)
    active.update(state='active', version='2')
    terminal = copy.deepcopy(active)
    terminal.update(state='deactivated', version='3')
    expired_created = copy.deepcopy(created)
    expired_created['keys'] = expired_created['keys'][:2]
    expired_created['keys'][0]['expires'] = 101
    expired_active = copy.deepcopy(expired_created)
    expired_active.update(state='active', version='2')
    repaired = copy.deepcopy(expired_active)
    repaired['version'] = '3'
    repaired['keys'].append(copy.deepcopy(base['keys'][2]))
    updated = copy.deepcopy(repaired)
    updated['version'] = '4'
    updated['services'] = [{'name': 'api', 'type': 'Agent',
                            'uri': 'https://agents.example.com/api'}]
    cases = {
        'create': (created, 100, 'create', '', True, True),
        'wrong-source-open': (active, 150, 'activate', '1', False, True),
        'activate': (active, 200, 'activate', '1', False, True),
        'missing-credentials': (terminal, 250, 'deactivate', '2', False, False),
        'stale-version': (terminal, 300, 'deactivate', '1', False, True),
        'deactivate': (terminal, 300, 'deactivate', '2', False, True),
        'terminal-reuse': (created, 400, 'create', '', False, True),
        'incomplete-restart': (created, 500, 'create', '', False, True),
        'expired-create': (expired_created, 100, 'create', '', True, True),
        'expired-activate': (expired_active, 100, 'activate', '1', False, True),
        'expired-repair': (repaired, 200, 'add-key', '2', False, True),
        'recovered-service-update': (updated, 300, 'update-services', '3', False, True),
    }
    return cases[mode]


def request(base, row, journal_path):
    record, now, operation, version, create, authenticated = materialize(
        base['body']['record'], row['mode'])
    envelope = json.dumps({'record': record, 'issued': now, 'expires': now + 5},
                          separators=(',', ':')).encode()
    payload = {
        'action': 'journal-transaction', 'did': base['expected_did'],
        'candidate': base64.urlsafe_b64encode(envelope).rstrip(b'=').decode(),
        'candidate_now': now, 'operation': operation, 'expected_version': version,
        'fixture_actor': 'operator', 'fixture_scope': '',
        'fixture_authenticated': authenticated,
        'fixture_source': ('other-origin' if row['mode'] == 'wrong-source-open'
                           else 'trusted-web-origin'),
        'trusted_source': 'trusted-web-origin',
        'journal_path': str(journal_path), 'journal_create': create,
    }
    encoded = json.dumps(payload, separators=(',', ':'))
    require(len(encoded.encode()) <= 150000, 'journal request bound')
    return encoded


def run_case(binary, base, row, journal_path):
    if row['mode'] == 'incomplete-restart':
        with journal_path.open('ab') as stream:
            stream.write(b'{"incomplete":')
            stream.flush()
    process = subprocess.run([str(binary)], input=request(base, row, journal_path),
                             text=True, capture_output=True, timeout=10, check=False)
    if expectation(row['mode']) == {'exit_code': 2}:
        require(process.returncode == 2 and not process.stdout and not process.stderr,
                'journal open must fail closed: ' + row['id'])
        return {'exit_code': process.returncode}
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'journal adapter failed: ' + row['id'])
    actual = json.loads(process.stdout)
    expected = expectation(row['mode'])
    require(type(actual) is dict and set(actual) == set(expected) and
            type(actual['verdict']) is str and
            type(actual['committed']) is bool and
            type(actual['history_len']) is int and
            type(actual['tombstoned']) is bool,
            'journal adapter result: ' + row['id'])
    return actual


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 journal fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'proof_fixture', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-local-durable-write-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            suite['proof_fixture'] == 'reg08-record-proofs.json:base' and
            len(suite['cases']) == len(EXPECTED), 'journal suite identity')
    seen = {name: [] for name in SEQUENCES}
    for row in suite['cases']:
        require(set(row) == {'id', 'sequence', 'mode', 'expected'} and
                row['sequence'] in SEQUENCES and row['mode'] in EXPECTED and
                row['expected'] == expectation(row['mode']), 'journal case fields')
        seen[row['sequence']].append(row['mode'])
    require(seen == SEQUENCES, 'journal case order')
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
    with tempfile.TemporaryDirectory(prefix='sage-reg08-journal-') as temporary:
        workspace = Path(temporary)
        binaries = build(go_root, rust_root, workspace, lock_source)
        subjects = {}
        for name, binary in binaries.items():
            cases = []
            for row in suite['cases']:
                journal_path = workspace / (name + '-' + row['sequence'] + '.journal')
                actual = run_case(binary, base, row, journal_path)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual, 'match': actual == row['expected']})
            subjects[name] = {
                'source_revision': revisions[name],
                'executable_sha256': sha(binary.read_bytes()),
                'matched': sum(case['match'] for case in cases),
                'total': len(cases), 'cases': cases,
            }
    require(all(item['matched'] == len(EXPECTED) for item in subjects.values()),
            'core durable journal mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-local-durable-write-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'local_durable_write_journal': 'BOUNDED',
        'authenticated_source_history': 'NOT_RUN',
        'credential_authentication': 'NOT_RUN',
        'delegation_state_provenance': 'NOT_RUN',
        'deployed_atomic_write': 'NOT_RUN',
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
        parser.exit(1, 'REG-08 journal observation FAIL: ' + str(error) + '\n')
    print('REG-08 local journal: Go 12/12, Rust 12/12; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
