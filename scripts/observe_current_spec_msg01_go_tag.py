"""Recheck the independently signed MSG-01 control with the updated Go core."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from check_current_spec_msg01_vectors import check as check_vectors
from current_spec_catalog import ROOT, load, require, sha
from observe_reconciled_reg08_record_shape import revision


GO_REVISION = '5a1b57ff5296a65cf01c03514944629b3c84ae20'
VECTOR = 'vectors/0.10.0/current-spec/MSG-01-P.json'
ADAPTER = 'adapters/go/msg01-tag/main.go'
REPORT = 'docs/evidence/current-spec/msg01/go-tag-observation.json'
TAG = b';tag="sage-0.10.0"'


def fixture(root=ROOT):
    require(check_vectors(root) == 5, 'independent MSG-01 fixture check failed')
    raw = (root / VECTOR).read_bytes()
    value = load(raw)
    require(value['id'] == 'MSG-01-P' and
            value['input']['operation'] == 'http.msg01.primitives' and
            value['expected']['verdict'] == 'ACCEPT', 'MSG-01 control identity')
    return value, sha(raw)


def check_report(report, root=ROOT):
    control, digest = fixture(root)
    require(set(report) == {'schema_version', 'kind', 'go_revision',
                            'vector_sha256', 'adapter_sha256', 'runner_sha256',
                            'observations', 'scope', 'conformance'} and
            report['schema_version'] == 1 and
            report['kind'] == 'msg01-go-tag-observation' and
            report['go_revision'] == GO_REVISION and
            report['vector_sha256'] == digest and
            report['adapter_sha256'] == sha((root / ADAPTER).read_bytes()) and
            report['runner_sha256'] == sha(Path(__file__).read_bytes()) and
            report['scope'] == 'signature-base-and-ed25519-only' and
            report['conformance'] == 'NOT_ESTABLISHED',
            'MSG-01 observation identity or scope')
    expected = control['expected']['output']['base_hex']
    require(report['observations'] == {
        'signed_control': {'base_hex': expected, 'signature_valid': True},
        'changed_tag': {'base_matches_control': False,
                        'signature_valid': False}},
        'MSG-01 observation did not retain both signature boundaries')
    return True


def invoke(binary, wire, public):
    payload = {'request_hex': wire.hex(), 'public_key_hex': public}
    process = subprocess.run([str(binary)], input=json.dumps(payload),
                             text=True, capture_output=True, timeout=15)
    require(process.returncode == 0 and not process.stderr and
            len(process.stdout) <= 4096, 'Go MSG-01 adapter failed')
    result = json.loads(process.stdout)
    require(set(result) == {'base_hex', 'signature_valid'} and
            type(result['signature_valid']) is bool and
            type(result['base_hex']) is str,
            'Go MSG-01 adapter result shape')
    return result


def observe(go_root, root=ROOT):
    require(revision(go_root) == GO_REVISION,
            'Go core revision mismatch or dirty checkout')
    control, digest = fixture(root)
    source = control['input']['input']
    wire = bytes.fromhex(source['request_hex'])
    require(wire.count(TAG) == 1, 'MSG-01 control tag changed')
    changed = wire.replace(TAG, b';tag="sage-0.10.1"', 1)
    with tempfile.TemporaryDirectory(prefix='sage-msg01-tag-') as temporary:
        binary = Path(temporary) / 'go-msg01-tag'
        environment = os.environ.copy()
        environment['GOCACHE'] = str(Path(temporary) / 'go-cache')
        subprocess.run(['go', 'build', '-o', str(binary), str(root / ADAPTER)],
                       cwd=go_root, env=environment, check=True, timeout=300)
        positive = invoke(binary, wire, source['public_key_hex'])
        negative = invoke(binary, changed, source['public_key_hex'])
    report = {
        'schema_version': 1, 'kind': 'msg01-go-tag-observation',
        'go_revision': GO_REVISION, 'vector_sha256': digest,
        'adapter_sha256': sha((root / ADAPTER).read_bytes()),
        'runner_sha256': sha(Path(__file__).read_bytes()),
        'observations': {
            'signed_control': positive,
            'changed_tag': {
                'base_matches_control': negative['base_hex'] ==
                                        control['expected']['output']['base_hex'],
                'signature_valid': negative['signature_valid'],
            },
        },
        'scope': 'signature-base-and-ed25519-only',
        'conformance': 'NOT_ESTABLISHED',
    }
    check_report(report, root)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-root', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = observe(args.go_root.resolve())
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('MSG-01 Go signature base: signed control PASS; changed tag REJECT')
