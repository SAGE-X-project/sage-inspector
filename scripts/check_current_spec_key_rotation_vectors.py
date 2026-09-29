"""Audit an exact replay after signing-key authority is withdrawn."""

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from current_spec_catalog import ROOT, load, require, sha
from generate_current_spec_key_rotation_vectors import ID, SPEC, case


def check(root=ROOT):
    suite = load((root / 'vectors/0.10.0/exec-key-rotation.json').read_bytes())
    source = root / 'vectors/0.10.0/guard-records.json'
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    inp, expected = case()
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] ==
            manifest['source_sha256']['profiles/agent-mcp-security.md'] and
            suite['source_bytes_sha256'] == sha(source.read_bytes()) and
            suite['case'] == {'id': ID, 'input': inp, 'expected': expected},
            'pinned key-rotation case')
    relative = f'vectors/0.10.0/current-spec/{ID}.json'
    raw = (root / relative).read_bytes()
    require(load(raw) == {'schema_version': 1, 'spec_revision': SPEC,
                          'id': ID, 'track': 'runtime', 'input': inp,
                          'expected': expected} and
            any(row == {'id': ID, 'track': 'runtime', 'fixture': relative,
                        'fixture_sha256': sha(raw), 'coverage': 'partial'}
                for row in bindings['bindings']), 'partial replay binding')
    stages = inp['input']['stages']
    first, second = stages
    base = first['actions'][0]['input']
    rotated = second['actions'][0]['input']
    envelope = load(bytes.fromhex(base['envelope_hex']))
    signature = base64.urlsafe_b64decode(envelope['proof'] + '=' *
                                         (-len(envelope['proof']) % 4))
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(
        base['public_key_hex'])).verify(
            signature, b'sage-execution-intent|0.10.0\x00' +
            json.dumps(envelope['intent'], sort_keys=True,
                       separators=(',', ':')).encode())
    require(first['mode'] == 'create' and second['mode'] == 'reopen' and
            base['active_key'] is True and rotated['active_key'] is False and
            {k: v for k, v in base.items() if k != 'active_key'} ==
            {k: v for k, v in rotated.items() if k != 'active_key'} and
            first['actions'][1] == second['actions'][1] and
            expected['effects'] == {'dispatch': 1} and
            expected['output']['journal_states'] ==
            ['RESERVED', 'EXECUTING', 'UNKNOWN'],
            'one old send and no replay after key withdrawal')
    return 1


if __name__ == '__main__':
    print(check())
