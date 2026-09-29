"""Independently audit signed intent, schema, size, and identity probes."""

import base64
import copy
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from current_spec_catalog import ROOT, load, require, sha


SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = tuple('EXEC-03-' + suffix for suffix in
            ('P', 'N01', 'N02', 'N03', 'N04', 'N05'))
SOURCE = 'vectors/0.10.0/exec03-intents.json'
HISTORICAL_SHA = '68bd8c57a9a572849ea5f57f77d93c0e7d2fe813ea7b158c47b24c832efdef0f'


def envelope(inp):
    return load(bytes.fromhex(inp['envelope_hex']))


def signature_valid(inp):
    value = envelope(inp)
    proof = value['proof']
    raw = base64.urlsafe_b64decode(proof + '=' * (-len(proof) % 4))
    canonical = json.dumps(value['intent'], sort_keys=True,
                           separators=(',', ':'), ensure_ascii=False).encode()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(
            inp['public_key_hex'])).verify(
                raw, b'sage-execution-intent|0.10.0\x00' + canonical)
        return True
    except InvalidSignature:
        return False


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == manifest['source_sha256'][
                'profiles/agent-mcp-security.md'] and
            suite['historical_bytes_sha256'] == HISTORICAL_SHA ==
            sha((root / 'vectors/0.10.0/guard-records.json').read_bytes()) and
            suite['scope'] == 'intent verifier and generic JSON size primitives; no outer HTTP binding, dispatch, or full case conformance claim' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'EXEC-03 source and scope')
    good, changed, unknown, oversized, nonce, identity = [
        row['input'] for row in suite['cases']]
    valid = envelope(good)
    altered = envelope(changed)
    unexpected = envelope(unknown)
    bad_nonce = envelope(nonce)
    require(set(valid) == {'intent', 'proof'} and
            set(valid['intent']) == {'version', 'profile', 'request_id', 'call_id',
                                     'parent_call_id', 'original_digest', 'issuer',
                                     'recipient', 'tool', 'arguments', 'policy_digest',
                                     'manifest_digest', 'created', 'expires', 'nonce',
                                     'keyid', 'alg'} and
            signature_valid(good) and
            valid['proof'] == altered['proof'] and
            not signature_valid(changed) and
            {**valid['intent'], 'arguments': altered['intent']['arguments']} ==
            altered['intent'],
            'valid signature and isolated post-signature argument mutation')
    require(signature_valid(unknown) and
            unexpected['intent'] == dict(valid['intent'], extra=True) and
            unexpected['proof'] != valid['proof'],
            'independently signed unknown field')
    require(oversized == {'prefix_hex': '7b2264617461223a22',
                          'repeat_byte': 97, 'repeat_count': 1048566,
                          'suffix_hex': '227d'} and
            len(bytes.fromhex(oversized['prefix_hex'])) +
            oversized['repeat_count'] +
            len(bytes.fromhex(oversized['suffix_hex'])) == 1048577,
            '1 MiB plus one byte JSON recipe')
    clone = copy.deepcopy(valid)
    clone['intent']['nonce'] = 'bad'
    require(bad_nonce == clone and not signature_valid(nonce) and
            envelope(identity) == valid and
            identity['expected_recipient'] == valid['intent']['issuer'] and
            identity['expected_recipient'] != valid['intent']['recipient'],
            'isolated malformed nonce and executor identity mismatch')
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    for index, row in enumerate(suite['cases']):
        ident = IDS[index]
        expected = {'verdict': 'ACCEPT' if index == 0 else 'REJECT',
                    'output': {'valid': True} if index == 0 else {},
                    'effects': {}}
        operation = ('sage.guard.json.bounds' if index == 3 else
                     'sage.guard.intent.verify')
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(row['operation'] == operation and row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                            'track': 'runtime',
                            'input': {'operation': operation, 'input': row['input']},
                            'expected': expected},
                'EXEC-03 case contract: ' + ident)
        require(any(binding == {'id': ident, 'track': 'runtime',
                                'fixture': path,
                                'fixture_sha256': sha((root / path).read_bytes()),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'EXEC-03 partial runtime binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
