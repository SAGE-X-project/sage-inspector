"""Audit signed policy-denial fixtures against pinned source bytes."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from current_spec_catalog import ROOT, load, require, sha
from generate_current_spec_policy_admission_vectors import CASES, SPEC, cases


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode()


def check(root=ROOT):
    suite = load((root / 'vectors/0.10.0/exec-policy-admission.json').read_bytes())
    source = root / 'vectors/0.10.0/guard-records.json'
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] ==
            manifest['source_sha256']['profiles/agent-mcp-security.md'] and
            suite['historical_bytes_sha256'] == sha(source.read_bytes()) and
            [row['id'] for row in suite['cases']] ==
            [ident for ident, _ in CASES], 'pinned policy-admission sources')
    for row, (ident, inp, expected) in zip(suite['cases'], cases()):
        payload = {'operation': 'sage.guard.intent.verify', 'input': inp}
        require(row == {'id': ident, 'input': payload,
                        'expected': expected}, 'policy-admission case')
        relative = f'vectors/0.10.0/current-spec/{ident}.json'
        raw = (root / relative).read_bytes()
        require(load(raw) == {'schema_version': 1, 'spec_revision': SPEC,
                              'id': ident, 'track': 'runtime',
                              'input': payload, 'expected': expected} and
                any(binding == {'id': ident, 'track': 'runtime',
                                'fixture': relative,
                                'fixture_sha256': sha(raw),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'partial policy-admission binding')
        envelope = load(bytes.fromhex(inp['envelope_hex']))
        proof = base64.urlsafe_b64decode(envelope['proof'] + '=' *
                                         (-len(envelope['proof']) % 4))
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(inp['public_key_hex'])).verify(
                proof, b'sage-execution-intent|0.10.0\x00' +
                canonical(envelope['intent']))
        local_digest = hashlib.sha256(b'sage-policy|0.10.0\x00' +
                                      canonical(inp['approved_policy'])).hexdigest()
        if ident == 'EXEC-02-N03':
            require(envelope['intent']['policy_digest'] == local_digest and
                    inp['policy_allow'] is False,
                    'matching digest does not grant policy permission')
        else:
            require(envelope['intent']['policy_digest'] != local_digest and
                    inp['policy_allow'] is True,
                    'incoming descriptor cannot replace approved mapping')
    return len(CASES)


if __name__ == '__main__':
    print(check())
