"""Check HPKE-02 B/info/exportCtx and isolated identity/state conditions."""

import base64
import hashlib
import json

from current_spec_catalog import ROOT, load, require


IDS = ('HPKE-02-P', 'HPKE-02-N01', 'HPKE-02-N02',
       'HPKE-02-N03', 'HPKE-02-N04')
EXPORTER = 'a8de62cfb50aae8058d494a86b9420a9a04fbb5f19c4b25bda7c4cf251aa882c'
B_FIELDS = ('v', 'ctx', 'initDid', 'respDid', 'initKid', 'respKid',
            'kemKid', 'suite', 'combiner', 'nonce')


def binary(value, size):
    require(type(value) is str, 'HPKE-02 binary field type')
    decoded = base64.urlsafe_b64decode(value + '==')
    require(len(decoded) == size and
            base64.urlsafe_b64encode(decoded).decode().rstrip('=') == value,
            'HPKE-02 canonical base64url field')
    return decoded


def check(root=ROOT):
    fixtures = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime',
                'HPKE-02 fixture identity')
        fixtures[ident] = fixture

    source = next(row for row in load(
        (root / 'vectors/0.10.0/hpke-derivation010.json').read_bytes())['cases']
        if row['id'] == 'schedule-0-responder')
    raw = bytes.fromhex(source['input']['initiation_hex'])
    init = load(raw)
    require(raw == json.dumps(init, sort_keys=True,
                              separators=(',', ':')).encode() and
            set(init) == set(B_FIELDS) | {'task', 'enc', 'ephC'} and
            init['v'] == '0.10.0' and init['task'] == 'hpke/init@0.10.0' and
            init['suite'] == 'hpke-base+x25519+hkdf-sha256' and
            init['combiner'] == 'e2e-x25519-hkdf-v1' and
            init['initKid'] == init['initDid'] + '#signing-1' and
            init['respKid'] == init['respDid'] + '#signing-1' and
            init['kemKid'] == init['respDid'] + '#kem-1' and
            binary(init['enc'], 32) != binary(init['ephC'], 32) and
            len(binary(init['nonce'], 16)) == 16,
            'HPKE-02 complete canonical initiation and distinct public ephemerals')

    binding = {field: init[field] for field in B_FIELDS}
    info = (b'sage-hpke-info|0.10.0\n' +
            json.dumps(binding, sort_keys=True,
                       separators=(',', ':')).encode())
    export_context = (b'sage-hpke-export|0.10.0\n' +
                      hashlib.sha256(info).digest())
    anchor = next(row for row in load(
        (root / 'vectors/0.10.0/hpke-primitives.json').read_bytes())['cases']
        if row['id'] == 'sage-export-0')
    positive = fixtures['HPKE-02-P']
    require(anchor['operation'] == 'rfc9180.export' and
            anchor['input']['enc_hex'] == binary(init['enc'], 32).hex() and
            anchor['input']['info_hex'] == info.hex() and
            anchor['input']['export_context_hex'] == export_context.hex() and
            anchor['expected'] == {'verdict': 'ACCEPT',
                                   'output': {'exporter_hex': EXPORTER}} and
            positive['input'] == {'operation': 'rfc9180.export',
                                  'input': anchor['input']} and
            positive['expected'] == {'verdict': 'ACCEPT',
                                     'output': {'exporter_hex': EXPORTER},
                                     'effects': {}},
            'HPKE-02 exact B/info/exportCtx exporter control')

    context = {
        'initiation_hex': raw.hex(),
        'authenticated_initiator_did': init['initDid'],
        'authenticated_responder_did': init['respDid'],
        'authenticated_context_id': init['ctx'],
        'authenticated_nonce': init['nonce'],
        'selected_initiator_signing_kid': init['initKid'],
        'selected_responder_signing_kid': init['respKid'],
        'selected_responder_kem_kid': init['kemKid'],
        'prior_contexts': [], 'prior_nonces': [],
    }
    scenarios = {
        'HPKE-02-N01': dict(context,
            authenticated_initiator_did='did:sage:web:agent.example:mallory'),
        'HPKE-02-N02': dict(context,
            authenticated_context_id='22222222-2222-4222-8222-222222222222'),
        'HPKE-02-N03': dict(context, prior_nonces=[{
            'initDid': init['initDid'], 'respDid': init['respDid'],
            'nonce': init['nonce']}]),
        'HPKE-02-N04': dict(context,
            selected_responder_signing_kid=init['respDid'] + '#signing-2'),
    }
    for ident, expected_input in scenarios.items():
        fixture = fixtures[ident]
        require(fixture['input'] == {'operation': 'sage.hpke.init.verify',
                                     'input': expected_input} and
                fixture['expected'] == {
                    'verdict': 'REJECT', 'output': {},
                    'effects': {'sessions_created': 0,
                                'protected_dispatches': 0}},
                'HPKE-02 isolated authenticated-context denial: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print('Verified HPKE-02 binding fixtures:', check())
