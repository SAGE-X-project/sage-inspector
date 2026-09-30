"""Observe pinned Go and Rust checks over asserted web Registry histories."""

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


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-history-continuity.json'
VECTOR_SHA256 = 'f8b83d9a0ea2567c3f4586bd6ba4bbe05e77f4da323cf69334e3e2555ac10d22'
GO_REVISION = '7f1903618524407bc717a685d31ad7814a1edbfb'
RUST_REVISION = 'b486bb2ab0ae40a2444eb0a6d414027ea1239c4b'
ACCEPT = {'complete-services', 'single-create', 'complete-terminal'}
REJECT = {
    'missing-creation', 'skipped-version', 'repeated-version',
    'wrong-operation', 'controller-transfer', 'removed-key',
    'time-regression', 'future-mutation', 'stale-current',
    'altered-current', 'post-terminal', 'invalid-creation',
}
EXPECTED = {mode: 'TRANSITION_ACCEPT' for mode in ACCEPT} | {
    mode: 'RECORD_INVALID' for mode in REJECT}


def materialize(base, mode):
    created = copy.deepcopy(base)
    created['state'] = 'created'
    created['version'] = '1'
    active = copy.deepcopy(created)
    active['state'] = 'active'
    active['version'] = '2'
    updated = copy.deepcopy(active)
    updated['version'] = '3'
    updated['services'] = [{'name': 'api', 'type': 'Agent',
                            'uri': 'https://agents.example.com/api'}]
    terminal = copy.deepcopy(updated)
    terminal['version'] = '4'
    terminal['state'] = 'deactivated'
    history = [
        {'record': created, 'at': 100, 'operation': 'create'},
        {'record': active, 'at': 101, 'operation': 'activate'},
        {'record': updated, 'at': 102, 'operation': 'update-services'},
    ]
    current = copy.deepcopy(updated)

    if mode == 'single-create':
        history = history[:1]
        current = copy.deepcopy(created)
    elif mode == 'complete-terminal':
        history.append({'record': terminal, 'at': 103, 'operation': 'deactivate'})
        current = copy.deepcopy(terminal)
    elif mode == 'missing-creation':
        history = history[1:]
    elif mode == 'skipped-version':
        history.pop(1)
    elif mode == 'repeated-version':
        history[2]['record']['version'] = '2'
    elif mode == 'wrong-operation':
        history[2]['operation'] = 'add-key'
    elif mode == 'controller-transfer':
        history[2]['record']['controller'] = 'other-operator'
    elif mode == 'removed-key':
        history[2]['record']['keys'].pop(1)
    elif mode == 'time-regression':
        history[2]['at'] = 99
    elif mode == 'future-mutation':
        history[2]['at'] = 105
    elif mode == 'stale-current':
        current = copy.deepcopy(active)
    elif mode == 'altered-current':
        current['services'][0]['uri'] = 'https://agents.example.com/other'
    elif mode == 'post-terminal':
        history.append({'record': terminal, 'at': 103, 'operation': 'deactivate'})
        later = copy.deepcopy(terminal)
        later['version'] = '5'
        history.append({'record': later, 'at': 103, 'operation': 'update-services'})
        current = copy.deepcopy(later)
    elif mode == 'invalid-creation':
        history[0]['record']['keys'][0]['state'] = 'revoked'
    elif mode != 'complete-services':
        raise ValueError('unknown history mode: ' + mode)
    return history, current


def request(base, row):
    history, current = materialize(base['body']['record'], row['mode'])
    encode = lambda value: base64.urlsafe_b64encode(envelope(value)).rstrip(b'=').decode()
    payload = {
        'action': 'history', 'did': base['expected_did'],
        'candidate': encode(current), 'candidate_now': 104,
        'history': [{'envelope': encode(item['record']), 'at': item['at'],
                     'operation': item['operation']} for item in history],
    }
    encoded = json.dumps(payload, separators=(',', ':'))
    require(len(encoded.encode()) <= 150000, 'history request bound')
    return encoded


def run_case(binary, base, row):
    process = subprocess.run([str(binary)], input=request(base, row), text=True,
                             capture_output=True, timeout=10, check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'history adapter failed: ' + row['id'])
    result = json.loads(process.stdout)
    require(type(result) is dict and set(result) == {'verdict'} and
            result['verdict'] in set(EXPECTED.values()),
            'history adapter verdict: ' + row['id'])
    return result['verdict']


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 history fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'proof_fixture', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-history-continuity-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            suite['proof_fixture'] == 'reg08-record-proofs.json:base' and
            len(suite['cases']) == len(EXPECTED), 'history suite identity')
    seen = set()
    for row in suite['cases']:
        require(set(row) == {'id', 'mode', 'expected'} and
                row['mode'] in EXPECTED and row['mode'] not in seen and
                row['expected'] == EXPECTED[row['mode']], 'history case fields')
        seen.add(row['mode'])
    require(seen == set(EXPECTED), 'history case set')
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
    with tempfile.TemporaryDirectory(prefix='sage-reg08-history-') as temporary:
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
            'core history mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-history-continuity-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'asserted_history_continuity': 'BOUNDED',
        'authenticated_source_history': 'NOT_RUN',
        'controller_authentication': 'NOT_RUN',
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
        parser.exit(1, 'REG-08 history observation FAIL: ' + str(error) + '\n')
    print('REG-08 asserted history: Go 15/15, Rust 15/15; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
