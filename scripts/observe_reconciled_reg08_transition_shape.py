"""Observe pinned Go and Rust web Registry creation and transition predicates."""

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from current_spec_catalog import ROOT, require, sha
from reconciled_spec_catalog import REVISION
from reconciled_spec_reg08_media import check
from observe_reconciled_reg08_record_shape import revision


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-transition-shape.json'
VECTOR_SHA256 = '3f8c18fb12e1e6b6998ae9f2e02719f25a7bd4470d96a08fe61771634bc9f2e0'
PROOFS = 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json'
PROOFS_SHA256 = '06e06202900d168a0faaceca101cc2c915b30ff5de61f0bb40fb7bc19afd91ab'
RUST_LOCK = 'verification/0.10.0/reconciled-spec/registry-tls-origin-Cargo.lock'
RUST_LOCK_SHA256 = '04099b5ee7c1320fb249112b1fba052aad1a433cc26d60e4537db108b69d6a38'
GO_REVISION = 'd83116b38d21fc9e7917978326c68019dd59d808'
RUST_REVISION = 'affa7385d6f6cd871a1fdd4a41e973eecdfbd311'
ACCEPT = {
    'create-valid', 'activate-valid', 'add-kem-valid', 'revoke-key-valid',
    'revoke-last-signer-terminal', 'deactivate-valid', 'service-update-valid',
    'revoke-kem-endorser-valid',
}
REJECT = {
    'create-revoked-endorser', 'skipped-version', 'controller-transfer',
    'add-kem-revoked-endorser', 'omit-retained-key', 'reaccept-revoked-key',
    'revoke-last-signer-active', 'reactivate-terminal',
    'add-key-with-service-change', 'change-key-expiry',
}
EXPECTED = {mode: 'TRANSITION_ACCEPT' for mode in ACCEPT} | {
    mode: 'RECORD_INVALID' for mode in REJECT}


def envelope(record):
    return json.dumps({'record': record, 'issued': 100, 'expires': 105},
                      separators=(',', ':')).encode()


def materialize(base, mode):
    before = copy.deepcopy(base)
    before['state'] = 'active'
    before['version'] = '2'
    candidate = copy.deepcopy(before)
    candidate['version'] = '3'
    operation = 'update-services'
    action = 'transition'

    if mode.startswith('create-'):
        action = 'create'
        before = None
        candidate = copy.deepcopy(base)
        candidate['state'] = 'created'
        candidate['version'] = '1'
        if mode == 'create-revoked-endorser':
            candidate['keys'][0]['state'] = 'revoked'
    elif mode in {'activate-valid', 'skipped-version', 'controller-transfer'}:
        before['state'] = 'created'
        before['version'] = '1'
        candidate['version'] = '2'
        candidate['state'] = 'active'
        operation = 'activate'
        if mode == 'skipped-version':
            candidate['version'] = '3'
        if mode == 'controller-transfer':
            candidate['controller'] = 'other-operator'
    elif mode in {'add-kem-valid', 'add-kem-revoked-endorser',
                  'add-key-with-service-change'}:
        operation = 'add-key'
        before['keys'].pop(1)
        if mode == 'add-kem-revoked-endorser':
            before['keys'][0]['state'] = 'revoked'
            candidate['keys'][0]['state'] = 'revoked'
        if mode == 'add-key-with-service-change':
            candidate['services'] = [{'name': 'api', 'type': 'Agent',
                                      'uri': 'https://agents.example.com/api'}]
    elif mode == 'omit-retained-key':
        candidate['keys'].pop(1)
    elif mode == 'reaccept-revoked-key':
        before['keys'][0]['state'] = 'revoked'
    elif mode == 'change-key-expiry':
        candidate['keys'][2]['expires'] = 104
    elif mode == 'revoke-key-valid':
        operation = 'revoke-key'
        candidate['keys'][2]['state'] = 'revoked'
    elif mode == 'revoke-kem-endorser-valid':
        operation = 'revoke-key'
        candidate['keys'][0]['state'] = 'revoked'
    elif mode in {'revoke-last-signer-terminal', 'revoke-last-signer-active'}:
        operation = 'revoke-key'
        before['keys'] = before['keys'][:2]
        candidate['keys'] = candidate['keys'][:2]
        candidate['keys'][0]['state'] = 'revoked'
        if mode == 'revoke-last-signer-terminal':
            candidate['state'] = 'deactivated'
    elif mode == 'deactivate-valid':
        operation = 'deactivate'
        candidate['state'] = 'deactivated'
    elif mode == 'reactivate-terminal':
        operation = 'activate'
        before['state'] = 'deactivated'
        candidate['state'] = 'active'
    elif mode == 'service-update-valid':
        candidate['services'] = [{'name': 'api', 'type': 'Agent',
                                  'uri': 'https://agents.example.com/api'}]
    else:
        raise ValueError('unknown transition mode: ' + mode)
    return action, before, candidate, operation


def request(base, row):
    action, before, candidate, operation = materialize(base['body']['record'], row['mode'])
    encode = lambda value: base64.urlsafe_b64encode(envelope(value)).rstrip(b'=').decode()
    payload = {
        'action': action, 'did': base['expected_did'],
        'previous': '' if before is None else encode(before),
        'candidate': encode(candidate), 'previous_now': base['now'],
        'candidate_now': base['now'], 'operation': operation,
    }
    encoded = json.dumps(payload, separators=(',', ':'))
    require(len(encoded.encode()) <= 150000, 'transition request bound')
    return encoded


def build(go_root, rust_root, output, lock_source):
    go_binary = output / 'sage-reg08-transition-go'
    go_env = os.environ.copy()
    go_env['GOCACHE'] = str(output / 'go-cache')
    subprocess.run(['go', 'build', '-o', str(go_binary),
                    './examples/registry-web-transition010'], cwd=go_root,
                   env=go_env, check=True, timeout=300)
    target_lock = rust_root / 'Cargo.lock'
    if target_lock.exists():
        require(sha(target_lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, target_lock)
    target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_web_transition010', '--target-dir', str(target)],
                   cwd=rust_root, check=True, timeout=600)
    rust_binary = target / 'debug' / 'examples' / 'registry_web_transition010'
    require(go_binary.is_file() and rust_binary.is_file(), 'transition adapters missing')
    return {'go': go_binary, 'rust': rust_binary}


def run_case(binary, base, row):
    process = subprocess.run([str(binary)], input=request(base, row), text=True,
                             capture_output=True, timeout=10, check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'transition adapter failed: ' + row['id'])
    result = json.loads(process.stdout)
    require(type(result) is dict and set(result) == {'verdict'} and
            result['verdict'] in set(EXPECTED.values()),
            'transition adapter verdict: ' + row['id'])
    return result['verdict']


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 transition fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'proof_fixture', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-transition-shape-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            suite['proof_fixture'] == 'reg08-record-proofs.json:base' and
            len(suite['cases']) == len(EXPECTED), 'transition suite identity')
    seen = set()
    for row in suite['cases']:
        require(set(row) == {'id', 'mode', 'expected'} and
                row['mode'] in EXPECTED and row['mode'] not in seen and
                row['expected'] == EXPECTED[row['mode']],
                'transition case fields')
        seen.add(row['mode'])
    require(seen == set(EXPECTED), 'transition case set')
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
    with tempfile.TemporaryDirectory(prefix='sage-reg08-transition-') as temporary:
        output = Path(temporary)
        binaries = build(go_root, rust_root, output, lock_source)
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
            'core transition mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-transition-shape-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'proof_fixture_sha256': PROOFS_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'creation_and_transition_shape': 'BOUNDED',
        'controller_authentication': 'NOT_RUN',
        'complete_authenticated_history': 'NOT_RUN',
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
        parser.exit(1, 'REG-08 transition observation FAIL: ' + str(error) + '\n')
    print('REG-08 transition shape: Go 18/18, Rust 18/18; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
