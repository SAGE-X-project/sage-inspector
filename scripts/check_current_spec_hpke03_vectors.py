"""Check HPKE-03 transcript, HKDF schedule, and isolated denials."""

import base64
import hashlib
import hmac
import json
import re

from current_spec_catalog import ROOT, load, require


IDS = ('HPKE-03-P', 'HPKE-03-N01', 'HPKE-03-N02',
       'HPKE-03-N03', 'HPKE-03-N04')
SEED = 'a670cc6a4cf4eed950a26f2e85a185457e283ba617fd87da485625d96a2a61a6'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def binary(value):
    require(type(value) is str, 'HPKE-03 binary value type')
    data = base64.urlsafe_b64decode(value + '==')
    require(base64.urlsafe_b64encode(data).decode().rstrip('=') == value,
            'HPKE-03 canonical base64url value')
    return data


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'HPKE-03 fixture identity')
    primitive = {row['id']: row for row in load((root /
        'vectors/0.10.0/hpke-primitives.json').read_bytes())['cases']}
    schedule = next(row for row in load((root /
        'vectors/0.10.0/hpke-derivation010.json').read_bytes())['cases']
        if row['id'] == 'schedule-0-responder')
    init = load(bytes.fromhex(schedule['input']['initiation_hex']))
    transcript_raw = bytes.fromhex(schedule['expected']['transcript_hex'])
    transcript = load(transcript_raw)
    require(transcript_raw == canonical(transcript) and
            set(transcript) == set(init) | {'ephS', 'kid'} and
            all(transcript[key] == value for key, value in init.items()) and
            len(binary(transcript['ephS'])) == 32 and
            binary(transcript['ephS']) != binary(transcript['ephC']) and
            re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-'
                         '[89ab][0-9a-f]{3}-[0-9a-f]{12}', transcript['kid'])
            is not None, 'HPKE-03 complete canonical transcript')
    th = hashlib.sha256(transcript_raw).digest()
    control = primitive['combiner-0']
    shared_hex = primitive['e2e-client']['expected']['output']['shared_secret_hex']
    require(control['operation'] == 'sage.hpke.combine' and
            control['input']['th_hex'] == th.hex() and
            control['input']['ss_e2e_hex'] == shared_hex ==
                primitive['e2e-server']['expected']['output']['shared_secret_hex'],
            'HPKE-03 transcript hash and two-sided X25519 secret')
    exporter = bytes.fromhex(control['input']['exporter_hex'])
    shared = bytes.fromhex(shared_hex)
    require(len(exporter) == len(shared) == 32 and any(shared),
            'HPKE-03 independent nonzero components')
    prk = hmac.digest(th, exporter + shared, 'sha256')
    seed = hmac.digest(prk, b'sage-hpke-combiner|0.10.0' + th + b'\x01', 'sha256')
    ack_key = hmac.digest(seed, b'sage-hpke-ack|0.10.0' + th + b'\x01', 'sha256')
    ack_tag = hmac.digest(ack_key, th, 'sha256')
    require(seed.hex() == SEED == schedule['expected']['seed_hex'] ==
            control['expected']['output']['seed_hex'] and
            ack_tag.hex() == schedule['expected']['ack_tag_hex'],
            'HPKE-03 independent RFC 5869 combiner and ACK answer')
    positive = fixtures['HPKE-03-P']
    require(positive['input'] == {'operation': control['operation'],
                                  'input': control['input']} and
            positive['expected'] == {'verdict': 'ACCEPT',
                'output': {'seed_hex': SEED}, 'effects': {}},
            'HPKE-03 positive core boundary')

    zero_dh = primitive['e2e-zero']
    zero_combiner = primitive['combiner-zero']
    for ident, source in (('HPKE-03-N01', zero_dh),
                          ('HPKE-03-N04', zero_combiner)):
        fixture = fixtures[ident]
        require(fixture['input'] == {'operation': source['operation'],
                                    'input': source['input']} and
                fixture['expected'] == {'verdict': 'REJECT',
                                        'output': {}, 'effects': {}},
                'HPKE-03 zero component denial: ' + ident)
    require(bytes.fromhex(zero_dh['input']['public_key_hex']) == bytes(32) and
            bytes.fromhex(zero_combiner['input']['ss_e2e_hex']) == bytes(32) and
            zero_combiner['input']['exporter_hex'] == control['input']['exporter_hex'] and
            zero_combiner['input']['th_hex'] == th.hex(),
            'HPKE-03 zero DH and exporter-only isolation')

    trusted = {'initiation_hex': schedule['input']['initiation_hex'],
               'transcript_hex': transcript_raw.hex(),
               'expected_responder_eph_s': transcript['ephS'],
               'expected_kid': transcript['kid']}
    wrong = dict(transcript, ctx='22222222-2222-4222-8222-222222222222')
    swapped = dict(transcript, ephC=transcript['ephS'],
                   ephS=transcript['ephC'])
    for ident, candidate in (('HPKE-03-N02', wrong),
                              ('HPKE-03-N03', swapped)):
        context = dict(trusted, transcript_hex=canonical(candidate).hex())
        require(fixtures[ident]['input'] == {
                    'operation': 'sage.hpke.transcript.verify',
                    'input': context} and fixtures[ident]['expected'] == {
                    'verdict': 'REJECT', 'output': {},
                    'effects': {'sessions_created': 0,
                                'protected_dispatches': 0}},
                'HPKE-03 isolated transcript denial: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print('Verified HPKE-03 transcript and combiner fixtures:', check())
