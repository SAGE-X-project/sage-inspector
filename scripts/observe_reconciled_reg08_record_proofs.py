"""Observe pinned Go and Rust REG-04 proofs in bounded web records."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from current_spec_catalog import ROOT, require, sha
from reconciled_spec_catalog import REVISION
from reconciled_spec_reg08_media import check
from observe_reconciled_reg08_record_shape import request, revision


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-record-proofs.json'
VECTOR_SHA256 = '06e06202900d168a0faaceca101cc2c915b30ff5de61f0bb40fb7bc19afd91ab'
RUST_LOCK = 'verification/0.10.0/reconciled-spec/registry-proofs-Cargo.lock'
RUST_LOCK_SHA256 = 'e69f4a88c561edbfa9423dc768d43081fb4753cac37f5bac5ac01a249f0465c7'
GO_REVISION = '3c09b4a497f4086e11ac5fa529ea933df32d7208'
RUST_REVISION = '061c2e489e3f388bcee113382167285e17b72064'
ACCEPT = {'valid-all-suites', 'historical-revoked-endorser',
          'historical-expired-endorser'}
REJECT = {
    'wrong-registry-proof', 'changed-ed-proof', 'small-order-ed-key',
    'small-order-ed-r', 'wrong-kem-signature', 'missing-kem-signer',
    'low-order-kem-key', 'invalid-p256-point', 'high-s-p256',
    'invalid-secp-point', 'high-s-secp', 'wrong-secp-recovery',
    'wrong-secp-digest',
}


def build(go_root, rust_root, output, lock_source):
    go_binary = output / 'sage-reg08-proofs-go'
    go_env = os.environ.copy()
    go_env['GOCACHE'] = str(output / 'go-cache')
    subprocess.run(['go', 'build', '-o', str(go_binary),
                    './examples/registry-record-proofs010'], cwd=go_root,
                   env=go_env, check=True, timeout=300)
    target_lock = rust_root / 'Cargo.lock'
    if target_lock.exists():
        require(sha(target_lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, target_lock)
    target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_record_proofs010', '--target-dir', str(target)],
                   cwd=rust_root, check=True, timeout=600)
    rust_binary = target / 'debug' / 'examples' / 'registry_record_proofs010'
    require(go_binary.is_file() and rust_binary.is_file(), 'proof adapters missing')
    return {'go': go_binary, 'rust': rust_binary}


def run_case(binary, base, row):
    process = subprocess.run([str(binary)], input=request(base, row), text=True,
                             capture_output=True, timeout=10, check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'proof adapter failed: ' + row['id'])
    response = json.loads(process.stdout)
    require(type(response) is dict and set(response) == {'verdict'} and
            response['verdict'] in {'PROOFS_ACCEPT', 'RECORD_INVALID',
                                    'SIZE_EXCEEDED'},
            'proof adapter verdict: ' + row['id'])
    return response['verdict']


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    """Record cryptographic decisions without granting Registry authority."""
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 proof fixture changed')
    suite = json.loads(raw)
    expected = {**dict.fromkeys(ACCEPT, 'PROOFS_ACCEPT'),
                **dict.fromkeys(REJECT, 'RECORD_INVALID')}
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'provenance', 'base', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-proof-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            len(suite['cases']) == len(expected), 'proof suite identity')
    seen = set()
    for row in suite['cases']:
        ident = row['id']
        require(ident in expected and ident not in seen and
                row['expected'] == expected[ident], 'proof case: ' + ident)
        request(suite['base'], row)
        seen.add(ident)
    require(seen == set(expected), 'proof case set')
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    actual_revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(actual_revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-proofs-') as temporary:
        binaries = build(go_root, rust_root, Path(temporary), lock_source)
        subjects = {}
        for name, binary in binaries.items():
            cases = []
            for row in suite['cases']:
                actual = run_case(binary, suite['base'], row)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual, 'match': actual == row['expected']})
            subjects[name] = {
                'source_revision': actual_revisions[name],
                'executable_sha256': sha(binary.read_bytes()),
                'matched': sum(case['match'] for case in cases),
                'total': len(cases), 'cases': cases,
            }
    require(all(item['matched'] == len(expected) and item['total'] == len(expected)
                for item in subjects.values()), 'core proof mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-proof-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'historical_signer_authority': 'NOT_RUN',
        'trusted_origin': 'NOT_RUN', 'controller_and_mutation_history': 'NOT_RUN',
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
        parser.exit(1, 'REG-08 core proof observation FAIL: ' + str(error) + '\n')
    print('REG-08 proofs: Go 16/16, Rust 16/16; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
