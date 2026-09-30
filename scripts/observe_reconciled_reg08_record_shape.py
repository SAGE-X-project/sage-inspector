"""Observe pinned Go and Rust REG-08 encoded-record structure decisions."""

import argparse
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
from observe_reconciled_reg08_media import RUST_LOCK, RUST_LOCK_SHA256, revision


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-record-shape.json'
VECTOR_SHA256 = 'eb391564d3a9c4677c80a20bbb9c1c740bcf7fa9a3e0839c44be8d6176647d5e'
GO_REVISION = '19c39080cc78918a307bc9008834874558bdd4c8'
RUST_REVISION = 'd13b4dff709a90428da4272ce45c1b1df48914b3'
ACCEPT = {'valid-active', 'valid-created-expired', 'valid-max-version',
          'valid-service-ip', 'record-at-limit'}
SIZE = {'record-over-limit'}
REJECT = {
    'wrong-record-id', 'malformed-expected-did', 'unknown-record-field',
    'missing-services', 'leading-zero-version', 'overflow-version',
    'empty-keys', 'unknown-algorithm', 'padded-key', 'private-key-field',
    'wrong-proof-signer', 'expired-active-key', 'fractional-key-expiry',
    'duplicate-key-material', 'unsorted-keys', 'service-name-collision',
    'service-http', 'service-userinfo', 'service-fragment',
    'service-bad-percent',
}


def location(root, path):
    require(type(path) is list and path and
            all(type(part) in (str, int) for part in path), 'record path')
    node = root
    for part in path[:-1]:
        node = node[part]
    return node, path[-1]


def request(base, row):
    """Materialize an ordinary JSON record with a bounded local mutation."""
    require(set(row) <= {'id', 'expected', 'expected_did', 'now', 'set',
                         'delete', 'copy_key', 'pad_record_to'}, 'record row fields')
    body = copy.deepcopy(base['body'])
    for change in row.get('set', []):
        require(set(change) == {'path', 'value'}, 'record mutation')
        parent, last = location(body, change['path'])
        parent[last] = change['value']
    for path in row.get('delete', []):
        parent, last = location(body, path)
        del parent[last]
    if 'copy_key' in row:
        change = row['copy_key']
        require(set(change) in ({'name', 'signer'}, {'name', 'signer', 'key'}),
                'record key copy')
        key = copy.deepcopy(body['record']['keys'][0])
        key['name'] = change['name']
        key['proof']['signer'] = change['signer']
        if 'key' in change:
            key['key'] = change['key']
        body['record']['keys'].append(key)
    if 'pad_record_to' in row:
        size = row['pad_record_to']
        require(size in (65536, 65537) and not row.get('set') and
                not row.get('delete') and 'copy_key' not in row, 'record padding')
        encoded = json.dumps(body['record'], separators=(',', ':'), ensure_ascii=True)
        require(encoded.startswith('{') and len(encoded) < size, 'record padding base')
        record = '{' + ' ' * (size - len(encoded)) + encoded[1:]
        content = ('{"record":' + record + ',"issued":100,"expires":105}')
        require(len(record.encode()) == size, 'exact encoded record size')
    else:
        content = json.dumps(body, separators=(',', ':'), ensure_ascii=True)
    result = {'body': content,
              'expected_did': row.get('expected_did', base['expected_did']),
              'now': row.get('now', base['now'])}
    require(type(result['expected_did']) is str and type(result['now']) is int and
            len(content) <= 69632, 'record request bound')
    return json.dumps(result)


def build(go_root, rust_root, output, lock_source):
    go_binary = output / 'sage-reg08-record-shape-go'
    go_env = os.environ.copy()
    go_env['GOCACHE'] = str(output / 'go-cache')
    subprocess.run(['go', 'build', '-o', str(go_binary),
                    './examples/registry-record-shape010'], cwd=go_root,
                   env=go_env, check=True, timeout=300)
    target_lock = rust_root / 'Cargo.lock'
    if target_lock.exists():
        require(sha(target_lock.read_bytes()) == RUST_LOCK_SHA256,
                'subject has a different local Cargo.lock')
    else:
        shutil.copyfile(lock_source, target_lock)
    target = output / 'rust-target'
    subprocess.run(['cargo', 'build', '--locked', '--example',
                    'registry_record_shape010', '--target-dir', str(target)],
                   cwd=rust_root, check=True, timeout=600)
    rust_binary = target / 'debug' / 'examples' / 'registry_record_shape010'
    require(go_binary.is_file() and rust_binary.is_file(), 'record adapters missing')
    return {'go': go_binary, 'rust': rust_binary}


def run_case(binary, base, row):
    process = subprocess.run([str(binary)], input=request(base, row), text=True,
                             capture_output=True, timeout=10, check=False)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 256, 'record adapter failed: ' + row['id'])
    response = json.loads(process.stdout)
    require(type(response) is dict and set(response) == {'verdict'} and
            response['verdict'] in {'SHAPE_ACCEPT', 'RECORD_INVALID',
                                    'SIZE_EXCEEDED'},
            'record adapter verdict: ' + row['id'])
    return response['verdict']


def observe(go_root, rust_root, spec_root=None, root=ROOT):
    """Record actual decisions without promoting complete REG-08 cases."""
    check(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 record fixture changed')
    suite = json.loads(raw)
    expected = {**dict.fromkeys(ACCEPT, 'SHAPE_ACCEPT'),
                **dict.fromkeys(REJECT, 'RECORD_INVALID'),
                **dict.fromkeys(SIZE, 'SIZE_EXCEEDED')}
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'base', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-record-shape-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            len(suite['cases']) == len(expected), 'record suite identity')
    seen = set()
    for row in suite['cases']:
        ident = row['id']
        require(ident in expected and ident not in seen and
                row['expected'] == expected[ident], 'record case: ' + ident)
        request(suite['base'], row)
        seen.add(ident)
    require(seen == set(expected), 'record case set')
    lock_source = root / RUST_LOCK
    require(sha(lock_source.read_bytes()) == RUST_LOCK_SHA256,
            'pinned Rust dependency lock changed')
    actual_revisions = {'go': revision(go_root), 'rust': revision(rust_root)}
    require(actual_revisions == {'go': GO_REVISION, 'rust': RUST_REVISION},
            'core source revision mismatch')
    with tempfile.TemporaryDirectory(prefix='sage-reg08-record-shape-') as temporary:
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
                for item in subjects.values()), 'core record shape mismatch')
    return {
        'schema_version': 1, 'kind': 'reg08-record-shape-core-observation',
        'spec_revision': REVISION, 'vector_sha256': VECTOR_SHA256,
        'rust_dependency_lock_sha256': RUST_LOCK_SHA256,
        'subjects': subjects,
        'parent_cases': {case: 'NOT_RUN' for case in
                         ('REG-08-P', 'REG-08-N01', 'REG-08-N02',
                          'REG-08-N03', 'REG-08-N04')},
        'trusted_origin': 'NOT_RUN', 'proof_verification': 'NOT_RUN',
        'complete_registry_record': 'NOT_RUN',
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
        parser.exit(1, 'REG-08 core record observation FAIL: ' + str(error) + '\n')
    print('REG-08 record shape: Go 26/26, Rust 26/26; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
