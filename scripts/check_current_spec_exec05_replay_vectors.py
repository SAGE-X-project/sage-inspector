"""Independently audit signed replay variants and one-effect expectations."""

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from current_spec_catalog import ROOT, load, require, sha


SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-05-N01', 'EXEC-05-N04', 'CST-01-01', 'CST-01-06')
SOURCE = 'vectors/0.10.0/exec05-replay.json'
HISTORICAL_SHA = '68bd8c57a9a572849ea5f57f77d93c0e7d2fe813ea7b158c47b24c832efdef0f'


def valid_signature(envelope_hex, public_hex):
    envelope = load(bytes.fromhex(envelope_hex))
    signature = base64.urlsafe_b64decode(envelope['proof'] + '=' *
                                         (-len(envelope['proof']) % 4))
    message = b'sage-execution-intent|0.10.0\x00' + json.dumps(
        envelope['intent'], sort_keys=True, separators=(',', ':')).encode()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            signature, message)
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
            suite['scope'] == 'inert local ledger replay only; no distributed replica, real tool effect, cancellation, or authorization inheritance claim' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'EXEC-05 source and scope')
    stages = [row['input']['input']['stages'] for row in suite['cases']]
    setup = stages[0][0]['actions'][0]
    original_hex = setup['input']['envelope_hex']
    original = load(bytes.fromhex(original_hex))
    public_hex = setup['input']['public_key_hex']
    nonce_hex = stages[0][0]['actions'][2]['envelope_hex']
    nonce = load(bytes.fromhex(nonce_hex))
    proof_hex = stages[3][0]['actions'][2]['envelope_hex']
    proof = load(bytes.fromhex(proof_hex))
    require(valid_signature(original_hex, public_hex) and
            valid_signature(nonce_hex, public_hex) and
            not valid_signature(proof_hex, public_hex) and
            original['intent']['call_id'] == nonce['intent']['call_id'] and
            original['intent']['nonce'] != nonce['intent']['nonce'] and
            {**original['intent'], 'nonce': nonce['intent']['nonce']} ==
            nonce['intent'] and
            proof['intent'] == original['intent'] and
            proof['proof'] != original['proof'],
            'changed nonce is independently signed; changed proof is invalid')
    require(stages[1][0]['actions'] == stages[1][1]['actions'][:2] and
            stages[1][1]['mode'] == 'reopen' and
            stages[1][1]['actions'][2] == stages[1][1]['actions'][1] and
            stages[2][0]['actions'][1] == stages[2][0]['actions'][2] and
            stages[0][0]['actions'][:2] == stages[2][0]['actions'][:2] ==
            stages[3][0]['actions'][:2],
            'exact-envelope retry and crash recovery sequences')
    raw = bytes.fromhex(original_hex)
    intent = original['intent']
    intent_sha = hashlib.sha256(raw).hexdigest()
    effect = {'instance': 'old', 'envelope_hex': original_hex,
              'arguments_hex': json.dumps(intent['arguments'], sort_keys=True,
                                          separators=(',', ':')).encode().hex(),
              'tool': intent['tool'], 'manifest_digest': intent['manifest_digest'],
              'intent_digest': intent_sha}
    effect_sha = hashlib.sha256(json.dumps(effect, sort_keys=True,
                                            separators=(',', ':')).encode()).hexdigest()
    blank = {'ok': True, 'created': False, 'committed': False,
             'state': '', 'intent_digest': '', 'effect_sha256': []}
    accepted = {'ok': True, 'created': True, 'committed': True,
                'state': 'EXECUTING', 'intent_digest': intent_sha,
                'effect_sha256': [effect_sha]}
    denied = dict(blank, ok=False, effect_sha256=[effect_sha])
    duplicate = dict(blank, state='EXECUTING', intent_digest=intent_sha,
                     effect_sha256=[effect_sha])
    unknown = dict(blank, state='UNKNOWN', intent_digest=intent_sha)
    expected = (
        {'verdict': 'REJECT', 'output': {
            'stages': [[blank, accepted, denied]],
            'journal_states': ['RESERVED', 'EXECUTING']},
         'effects': {'dispatch': 1}},
        {'verdict': 'ACCEPT', 'output': {
            'stages': [[blank, accepted], [blank, unknown, unknown]],
            'journal_states': ['RESERVED', 'EXECUTING', 'UNKNOWN']},
         'effects': {'dispatch': 1}},
        {'verdict': 'ACCEPT', 'output': {
            'stages': [[blank, accepted, duplicate]],
            'journal_states': ['RESERVED', 'EXECUTING']},
         'effects': {'dispatch': 1}},
        {'verdict': 'REJECT', 'output': {
            'stages': [[blank, accepted, denied]],
            'journal_states': ['RESERVED', 'EXECUTING']},
         'effects': {'dispatch': 1}},
    )
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    for index, row in enumerate(suite['cases']):
        ident = IDS[index]
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(row['expected'] == expected[index] and fixture == {
            'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
            'track': 'runtime', 'input': row['input'],
            'expected': expected[index]} and
            row['input']['operation'] == 'sage.guard.dispatch.sequence',
            'EXEC-05 case contract: ' + ident)
        require(any(binding == {'id': ident, 'track': 'runtime',
                                'fixture': path,
                                'fixture_sha256': sha((root / path).read_bytes()),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'EXEC-05 partial runtime binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
