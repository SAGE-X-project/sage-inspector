"""Check HPKE-01 suite and role-boundary fixtures without core code."""

import base64
import copy
import json
import re

from current_spec_catalog import ROOT, load, require


IDS = ('HPKE-01-P', 'HPKE-01-N01', 'HPKE-01-N02', 'HPKE-01-N03')
EXPORTER = '4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e'


def check(root=ROOT):
    fixtures = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime',
                'HPKE-01 fixture identity')
        fixtures[ident] = fixture

    positive = fixtures['HPKE-01-P']
    anchor = next(row for row in load(
        (root / 'vectors/0.10.0/hpke-primitives.json').read_bytes())['cases']
        if row['id'] == 'rfc9180-export-0')
    require(positive['input'] == {'operation': 'rfc9180.export',
                                  'input': anchor['input']} and
            anchor['expected'] == {'verdict': 'ACCEPT',
                                   'output': {'exporter_hex': EXPORTER}} and
            positive['expected'] == {'verdict': 'ACCEPT',
                                     'output': {'exporter_hex': EXPORTER},
                                     'effects': {}} and
            len(bytes.fromhex(anchor['input']['private_key_hex'])) == 32 and
            len(bytes.fromhex(anchor['input']['enc_hex'])) == 32,
            'HPKE-01 published Base exporter anchor')

    source = next(row for row in load(
        (root / 'vectors/0.10.0/hpke-derivation010.json').read_bytes())['cases']
        if row['id'] == 'schedule-0-responder')
    original = bytes.fromhex(source['input']['initiation_hex'])
    init = load(original)
    require(original == json.dumps(init, sort_keys=True,
                                   separators=(',', ':')).encode() and
            set(init) == {'v', 'task', 'ctx', 'initDid', 'respDid', 'initKid',
                          'respKid', 'kemKid', 'suite', 'combiner', 'nonce',
                          'enc', 'ephC'} and
            init['v'] == '0.10.0' and init['task'] == 'hpke/init@0.10.0' and
            init['suite'] == 'hpke-base+x25519+hkdf-sha256' and
            init['combiner'] == 'e2e-x25519-hkdf-v1' and
            re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
                         init['ctx']) is not None and
            init['initKid'] == init['initDid'] + '#signing-1' and
            init['respKid'] == init['respDid'] + '#signing-1' and
            init['kemKid'] == init['respDid'] + '#kem-1' and
            all(len(base64.urlsafe_b64decode(init[name] + '==')) == 32 for name
                in ('enc', 'ephC')),
            'HPKE-01 canonical initiation and distinct key roles')

    context = {
        'initiation_hex': original.hex(),
        'trusted_sender_envelope_status': 'authenticated',
        'trusted_sender_signing_key_status': 'active',
        'trusted_responder_signing_key_status': 'active',
        'trusted_responder_kem_key_status': 'active',
        'trusted_selected_kem_kid': init['kemKid'],
        'trusted_sender_signing_key_type': 'Ed25519',
        'trusted_responder_signing_key_type': 'Ed25519',
        'trusted_responder_kem_key_type': 'X25519',
    }
    mutated = copy.deepcopy(init)
    mutated['suite'] = 'hpke-base+x25519+hkdf-sha256+other'
    changed = dict(context, initiation_hex=json.dumps(
        mutated, sort_keys=True, separators=(',', ':')).encode().hex())
    scenarios = {
        'HPKE-01-N01': changed,
        'HPKE-01-N02': dict(context,
                            trusted_sender_envelope_status='missing_signature'),
        'HPKE-01-N03': dict(context,
                            trusted_responder_kem_key_status='revoked'),
    }
    for ident, expected_input in scenarios.items():
        fixture = fixtures[ident]
        require(fixture['input'] == {'operation': 'sage.hpke.establish',
                                     'input': expected_input} and
                fixture['expected'] == {
                    'verdict': 'REJECT', 'output': {},
                    'effects': {'sessions_created': 0,
                                'protected_dispatches': 0}},
                'HPKE-01 isolated establishment denial: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print('Verified HPKE-01 suite and role fixtures:', check())
