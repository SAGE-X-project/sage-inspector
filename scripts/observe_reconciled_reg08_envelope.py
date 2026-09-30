"""Observe the pinned REG-08 JSON envelope boundary in Go and Rust."""

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
from observe_reconciled_reg08_media import RUST_LOCK, RUST_LOCK_SHA256, revision


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-envelope.json'
VECTOR_SHA256 = '3b865d430d68d843a9c6a01397366dc95121af70eaef28c2183e5b6a11731bf7'
GO_REVISION = '628d36cce452762abb0c9e4a0e10b35d4a059529'
RUST_REVISION = '7658959e34f69ad100d085a0a04702dab8d8c2e4'
ACCEPT = {'issued-boundary', 'before-expiry', 'exact-exponent'}
SIZE = {'oversize'}
REJECT = {
    'at-expiry', 'before-issue', 'long-lifetime', 'zero-lifetime',
    'missing-record', 'nonobject-record', 'unknown-member', 'duplicate-root',
    'duplicate-nested', 'escaped-duplicate', 'negative-zero', 'lone-surrogate',
    'fractional-time', 'string-time', 'trailing-document', 'invalid-clock',
}


def request(row):
    """Materialize one bounded fixture without relying on either core."""
    require(type(row.get('now')) is int, 'envelope clock fixture')
    if 'body' in row:
        require(set(row) == {'id', 'body', 'now', 'expected'} and
                type(row['body']) is str, 'envelope body fixture')
        body = row['body']
    else:
        require(set(row) == {'id', 'repeat_byte', 'repeat_count', 'now', 'expected'} and
                row['repeat_byte'] == ' ' and row['repeat_count'] == 69633,
                'envelope body repetition fixture')
        body = row['repeat_byte'] * row['repeat_count']
    return json.dumps({'body': body, 'now': row['now']})


def build(go_root, rust_root, output, lock_source):
    """Compile fresh adapters with Inspector's pinned Rust lockfile."""
    go_binary = output / 'sage-reg08-envelope-go'
    go_env = os.environ.copy()
    go_env['GOCACHE'] = str(output / 'go-cache')
    subprocess.run(['go', 'build', '-o', str(go_binary),
                    './examples/registry-envelope010'], cwd=go_root,
                   env=go_env, check=True, timeout=300)
    target_lock = rust_root / 'Cargo.lock'
    if target_lock.exists():
        require(sha(target_lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, target_lock)
    rust_target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_envelope010', '--target-dir', str(rust_target)],
                   cwd=rust_root, check=True, timeout=600)
    rust_binary = rust_target / 'debug' / 'examples' / 'registry_envelope010'
    require(go_binary.is_file() and rust_binary.is_file(), 'adapter binary missing')
    return {'go': go_binary, 'rust': rust_binary}


def run_case(binary, row):
    process = subprocess.run([str(binary)], input=request(row), text=True,
                             capture_output=True, timeout=10, check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'adapter execution failed: ' + row['id'])
    response = json.loads(process.stdout)
    require(type(response) is dict and set(response) == {'verdict'} and
            response['verdict'] in {'ENVELOPE_ACCEPT', 'RECORD_INVALID',
                                    'SIZE_EXCEEDED'},
            'invalid adapter verdict: ' + row['id'])
    return response['verdict']


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    """Return bounded observations, leaving complete REG-08 cases unrun."""
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 envelope fixture changed')
    suite = json.loads(raw)
    expected = {**dict.fromkeys(ACCEPT, 'ENVELOPE_ACCEPT'),
                **dict.fromkeys(REJECT, 'RECORD_INVALID'),
                **dict.fromkeys(SIZE, 'SIZE_EXCEEDED')}
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-envelope-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            len(suite['cases']) == 20, 'envelope suite identity')
    seen = set()
    for row in suite['cases']:
        ident = row['id']
        require(ident in expected and ident not in seen and
                row['expected'] == expected[ident], 'envelope case: ' + ident)
        request(row)
        seen.add(ident)
    require(seen == set(expected), 'envelope case set')
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    actual_revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(actual_revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-envelope-') as temporary:
        binaries = build(go_root, rust_root, Path(temporary), lock_source)
        subjects = {}
        for name, binary in binaries.items():
            cases = []
            for row in suite['cases']:
                actual = run_case(binary, row)
                cases.append({'id': row['id'], 'expected': row['expected'],
                              'actual': actual, 'match': actual == row['expected']})
            subjects[name] = {
                'source_revision': actual_revisions[name],
                'executable_sha256': sha(binary.read_bytes()),
                'matched': sum(case['match'] for case in cases),
                'total': len(cases), 'cases': cases,
            }
    require(all(item['matched'] == 20 and item['total'] == 20
                for item in subjects.values()), 'core envelope mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-envelope-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'trusted_origin': 'NOT_RUN', 'complete_registry_record': 'NOT_RUN',
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
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        parser.exit(1, 'REG-08 core envelope observation FAIL: ' + str(error) + '\n')
    print('REG-08 envelope: Go 20/20, Rust 20/20; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
