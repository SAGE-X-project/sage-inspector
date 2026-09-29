"""Check HPKE-06 bounds, admission, and diagnostic fixture provenance."""

import base64
import json

from current_spec_catalog import ROOT, load, require


IDS = ('HPKE-06-P', 'HPKE-06-N01', 'HPKE-06-N02',
       'HPKE-06-N03', 'HPKE-06-N04')


def binary(value):
    require(type(value) is str, 'HPKE-06 binary field type')
    decoded = base64.urlsafe_b64decode(value + '==')
    require(base64.urlsafe_b64encode(decoded).decode().rstrip('=') == value,
            'HPKE-06 canonical binary field')
    return decoded


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'HPKE-06 fixture identity')
    source = {row['id']: row for row in load((root /
        'vectors/0.10.0/hpke-schedule.json').read_bytes())['cases']}
    valid = source['completion-valid']
    accepted = valid['expected']['output']
    for ident, anchor, length, verdict in (
            ('HPKE-06-P', 'completion-size-16384', 16384, 'ACCEPT'),
            ('HPKE-06-N01', 'completion-size-16385', 16385, 'REJECT'),
            ('HPKE-06-N02', 'short-ephS', 849, 'REJECT')):
        item = source[anchor]
        fixture = fixtures[ident]
        raw = bytes.fromhex(item['input']['completion_hex'])
        require(item['operation'] == 'sage.hpke.complete.verify' and
                len(raw) == length and
                fixture['input'] == {'operation': item['operation'],
                                     'input': item['input']} and
                item['expected']['verdict'] == verdict and
                fixture['expected']['verdict'] == verdict,
                'HPKE-06 completion boundary: ' + ident)
        if ident == 'HPKE-06-P':
            require(load(raw) == load(bytes.fromhex(valid['input']['completion_hex']))
                    and raw.endswith(b' ' * (length - len(bytes.fromhex(
                        valid['input']['completion_hex'])))) and
                    fixture['expected'] == {'verdict': 'ACCEPT',
                        'output': accepted, 'effects': {}},
                    'HPKE-06 exact size legal completion')
        elif ident == 'HPKE-06-N01':
            require(load(raw) == load(bytes.fromhex(valid['input']['completion_hex']))
                    and fixture['expected']['effects'] == {
                        'sessions_created': 0, 'protected_dispatches': 0},
                    'HPKE-06 over-limit completion has no effect')
        else:
            completion = load(raw)
            require(set(completion) == {'v', 'task', 'transcript',
                                        'ackTagB64', 'sigB64'} and
                    len(binary(completion['transcript']['ephS'])) != 32 and
                    fixture['expected']['effects'] == {
                        'sessions_created': 0, 'protected_dispatches': 0},
                    'HPKE-06 short fixed field denied before DH')
    require(bytes.fromhex(source['completion-size-16385']['input']
                          ['completion_hex']) ==
            bytes.fromhex(source['completion-size-16384']['input']
                          ['completion_hex']) + b' ',
            'HPKE-06 one-byte size crossing')

    initiation = valid['input']['pending']['initiation_hex']
    secret = valid['input']['pending']['hpke_ephemeral_private_hex']
    require(type(load(bytes.fromhex(initiation))) is dict and
            len(bytes.fromhex(secret)) == 32, 'HPKE-06 bounded controls')
    cookie = fixtures['HPKE-06-N03']
    require(cookie['input'] == {'operation': 'sage.hpke.init.admit',
            'input': {'initiation_hex': initiation,
                      'signed_envelope_present': False,
                      'cookie_metadata': {'opaque': 'local-admission-only'}}} and
            cookie['expected'] == {'verdict': 'REJECT',
                'output': {'error': 'authentication_failed'},
                'effects': {'sessions_created': 0, 'protected_dispatches': 0}},
            'HPKE-06 cookie cannot replace signed initiation')
    diagnostic = fixtures['HPKE-06-N04']
    require(diagnostic['input'] == {'operation': 'sage.hpke.init.admit',
            'input': {'initiation_hex': initiation,
                      'signed_envelope_present': False,
                      'diagnostic_secret_hex': secret}} and
            diagnostic['expected'] == {'verdict': 'REJECT',
                'output': {'error': 'authentication_failed'},
                'effects': {'secret_log_entries': 0,
                            'sessions_created': 0,
                            'protected_dispatches': 0}} and
            secret not in json.dumps(diagnostic['expected']),
            'HPKE-06 failure output and log secrecy expectation')
    return len(IDS)


if __name__ == '__main__':
    print('Verified HPKE-06 bounds/admission fixtures:', check())
