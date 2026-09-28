"""Reassess archived WebSocket/local gaps and bounded primitive observations."""

import base64
import copy
import hashlib
import json

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_transport06_vectors import check as check_vectors, IDS, SOURCE


BASE = ROOT / 'docs/evidence/current-spec/transport06'
RUNNER_REVISION = '8d0901ab8c6b3d229406445cc5b3d0e70c37b2d6'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 134,
            'PARTIAL': 33, 'NOT_RUN': 296}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 133,
              'PARTIAL': 40, 'NOT_RUN': 296}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def signature_input(root=ROOT):
    row = load((root / SOURCE).read_bytes())['cases'][0]
    wire = load(b''.join(bytes.fromhex(x) for x in row['fragments_hex']))
    unsigned = copy.deepcopy(wire)
    signature = base64.urlsafe_b64decode(unsigned.pop('signature') + '==')
    message = b'sage-wire-request|0.10.0\n' + json.dumps(
        unsigned, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()
    return {'algorithm': 'ed25519',
            'public_key_hex': row['trusted_public_key_hex'],
            'message_hex': message.hex(), 'signature_hex': signature.hex()}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == (5, 4),
            'independent TRANSPORT-06 fixture provenance')
    outcomes = {}
    for language, (repository, revision, executable_sha, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] ==
                    '5bcf511e604579afa63f434013447f44b6858828',
                'TRANSPORT-06 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 185 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred eighty-five bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'TRANSPORT-06 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'TRANSPORT-06 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'TRANSPORT-06 unavailable integrated receiver: ' +
                    language + '/' + ident)
        outcomes[language] = counts
    bounded = load((base / 'events/report.json').read_bytes())
    row = load((root / SOURCE).read_bytes())['cases'][0]
    envelope = b''.join(bytes.fromhex(x) for x in row['fragments_hex'])
    require(bounded['schema_version'] == 1 and
            bounded['spec_revision'] ==
                '5bcf511e604579afa63f434013447f44b6858828' and
            bounded['runner_revision'] == RUNNER_REVISION and
            bounded['scenario_sha256'] == sha((root / SOURCE).read_bytes()) and
            bounded['runner_sha256'] == sha((base / 'runner/run_current_spec_transport06_boundaries.py').read_bytes()) and
            bounded['bridge_sha256'] == sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) and
            bounded['parser_sha256'] == sha((base / 'runner/websocket010.py').read_bytes()) and
            bounded['signature_input'] == signature_input(root),
            'TRANSPORT-06 in-memory event and primitive provenance')
    events = bounded['events']
    require(events == {
        'schema_version': 1,
        'scope': 'in-memory Inspector wsproto event parser; no TLS, socket, or core receiver',
        'wsproto_version': '1.2.0', 'h11_version': '0.14.0',
        'fragmented_text': {'verdict': 'ACCEPT', 'messages': 1,
                            'envelope_sha256': hashlib.sha256(envelope).hexdigest()},
        'compressed_upgrade': {'verdict': 'REJECT'},
        'binary_event': {'verdict': 'REJECT'},
        'oversized_fragmented_message': 'UNIT_ONLY_COMPACT_LENGTHS',
        'unsigned_local_message': 'UNIT_ONLY_NO_CORE_RECEIVER',
    }, 'bounded parser observations and explicit untested limits')
    for language, (repository, revision, executable_sha, _) in REVISIONS.items():
        require(bounded['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                bounded['signature_observations'][language] == {
                    'schema_version': 1,
                    'case_id': 'TRANSPORT-06-P-signature',
                    'verdict': 'ACCEPT', 'output': {'valid': True}},
                'TRANSPORT-06 core signature primitive: ' + language)
    return outcomes


if __name__ == '__main__':
    print(check())
