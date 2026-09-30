"""Observe pinned Go and Rust web Registry lookup policy decisions."""

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
from observe_reconciled_reg08_record_shape import revision


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-origin-policy.json'
VECTOR_SHA256 = '9ddc3e93cdcfd1fcdc1c34c098c4ae7cb231e4f158a8d95f763be70710c9667d'
RUST_LOCK = 'verification/0.10.0/reconciled-spec/registry-proofs-Cargo.lock'
RUST_LOCK_SHA256 = 'e69f4a88c561edbfa9423dc768d43081fb4753cac37f5bac5ac01a249f0465c7'
GO_REVISION = '0654f923e307546ea383ca993c34be278a461a88'
RUST_REVISION = '833c9dc2c2eb9ef0892ba47a93aa9c2e2f761eda'
EXPECTED = {
    'exact-authorized-origin': 'POLICY_ACCEPT',
    'allowlist-with-other-origin': 'POLICY_ACCEPT',
    'no-allowlisted-origin': 'RECORD_UNREACHABLE',
    'http-origin-not-accepted': 'RECORD_UNREACHABLE',
    'origin-with-port-not-accepted': 'RECORD_UNREACHABLE',
    'different-origin-not-accepted': 'RECORD_UNREACHABLE',
    'ip-literal-did-invalid': 'RECORD_INVALID',
    'uppercase-domain-invalid': 'RECORD_INVALID',
    'redirect-status-unreachable': 'RECORD_UNREACHABLE',
    'not-modified-unreachable': 'RECORD_UNREACHABLE',
    'missing-no-store-invalid': 'RECORD_INVALID',
    'no-store-parameter-invalid': 'RECORD_INVALID',
    'wrong-media-invalid': 'RECORD_INVALID',
    'content-coding-invalid': 'RECORD_INVALID',
    'media-trailer-invalid': 'RECORD_INVALID',
}
URL = 'https://agents.example.com/.well-known/sage/agents/billing-bot'


def payload(base, row):
    require(set(row) == {'id', 'expected', 'overrides'}, 'origin case fields')
    require(type(row['overrides']) is dict and
            set(row['overrides']) <= set(base), 'origin overrides')
    request = {**base, **row['overrides']}
    require(set(request) == {'expected_did', 'allowed_origins', 'status',
                             'headers', 'trailers'}, 'origin request fields')
    encoded = json.dumps(request, separators=(',', ':'))
    require(len(encoded.encode()) <= 8192, 'origin request bound')
    return encoded


def build(go_root, rust_root, output, lock_source):
    go_binary = output / 'sage-reg08-origin-go'
    go_env = os.environ.copy()
    go_env['GOCACHE'] = str(output / 'go-cache')
    subprocess.run(['go', 'build', '-o', str(go_binary),
                    './examples/registry-web-origin-policy010'], cwd=go_root,
                   env=go_env, check=True, timeout=300)
    target_lock = rust_root / 'Cargo.lock'
    if target_lock.exists():
        require(sha(target_lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, target_lock)
    target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_web_origin_policy010', '--target-dir', str(target)],
                   cwd=rust_root, check=True, timeout=600)
    rust_binary = target / 'debug' / 'examples' / 'registry_web_origin_policy010'
    require(go_binary.is_file() and rust_binary.is_file(), 'origin adapters missing')
    return {'go': go_binary, 'rust': rust_binary}


def run_case(binary, base, row):
    process = subprocess.run([str(binary)], input=payload(base, row), text=True,
                             capture_output=True, timeout=10, check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 512, 'origin adapter failed: ' + row['id'])
    response = json.loads(process.stdout)
    require(type(response) is dict and set(response) == {'verdict', 'url'} and
            response['verdict'] in set(EXPECTED.values()) and
            type(response['url']) is str, 'origin adapter verdict: ' + row['id'])
    require(response['url'] == (URL if response['verdict'] == 'POLICY_ACCEPT' else ''),
            'origin adapter URL: ' + row['id'])
    return response


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    """Record policy subconditions without claiming a trusted network read."""
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 origin fixture changed')
    suite = json.loads(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'provenance', 'base', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-origin-policy-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            len(suite['cases']) == len(EXPECTED), 'origin suite identity')
    seen = set()
    for row in suite['cases']:
        ident = row['id']
        require(ident in EXPECTED and ident not in seen and
                row['expected'] == EXPECTED[ident], 'origin case: ' + ident)
        payload(suite['base'], row)
        seen.add(ident)
    require(seen == set(EXPECTED), 'origin case set')
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    actual_revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(actual_revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-origin-') as temporary:
        binaries = build(go_root, rust_root, Path(temporary), lock_source)
        subjects = {}
        for name, binary in binaries.items():
            cases = []
            for row in suite['cases']:
                actual = run_case(binary, suite['base'], row)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual['verdict'], 'url': actual['url'],
                              'match': actual['verdict'] == row['expected']})
            subjects[name] = {
                'source_revision': actual_revisions[name],
                'executable_sha256': sha(binary.read_bytes()),
                'matched': sum(case['match'] for case in cases),
                'total': len(cases), 'cases': cases,
            }
    require(all(item['matched'] == len(EXPECTED) for item in subjects.values()),
            'core origin policy mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-origin-policy-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'trusted_tls_origin_and_destination': 'NOT_RUN',
        'controller_and_mutation_history': 'NOT_RUN',
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
        parser.exit(1, 'REG-08 core origin observation FAIL: ' + str(error) + '\n')
    print('REG-08 origin policy: Go 15/15, Rust 15/15; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
