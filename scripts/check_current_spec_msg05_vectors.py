"""Check MSG-05 freshness and replay scenarios against the pinned rule."""

import base64
import copy

from current_spec_catalog import ROOT, load, require


IDS = ('MSG-05-P', 'MSG-05-N01', 'MSG-05-N02', 'MSG-05-N03',
       'MSG-05-N04', 'MSG-05-N05')


def check(root=ROOT):
    fixtures = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] == 'sage.http.freshness.verify',
                'MSG-05 fixture identity and scoped operation')
        fixtures[ident] = fixture

    control = fixtures['MSG-05-P']['input']['input']
    nonce = control['nonce']
    require(base64.urlsafe_b64encode(bytes(16)).rstrip(b'=').decode() == nonce
            and control['created'] == 1700000000
            and control['expires'] == 1700000300
            and control['trusted_now_unix'] == 1700000010
            and control['clock_trusted'] is True
            and control['sender_did'] == 'did:sage:web:agent.example:alice'
            and control['recipient_did'] == 'did:sage:web:agent.example:bob'
            and control['signing_key_id'] == 'signing-1'
            and control['replay'] == {'state': 'intact', 'prior': [], 'copies': 1},
            'MSG-05 canonical nonce and fresh control')
    require(fixtures['MSG-05-P']['expected'] ==
            {'verdict': 'ACCEPT', 'output': {'fresh': True, 'accepted': 1},
             'effects': {}}, 'MSG-05 positive scoped expectation')

    changes = {
        'MSG-05-N01': ('trusted_now_unix', 1700000330),
        'MSG-05-N02': ('trusted_now_unix', 1699999969),
        'MSG-05-N03': ('replay', {'state': 'intact', 'prior': [{
            'sender_did': control['sender_did'],
            'recipient_did': control['recipient_did'],
            'nonce': nonce, 'signing_key_id': 'signing-1'}], 'copies': 1}),
        'MSG-05-N04': ('replay', {'state': 'intact', 'prior': [], 'copies': 2}),
        'MSG-05-N05': ('replay', {'state': 'lost', 'prior': [], 'copies': 1,
                                'restart_elapsed_utc_seconds': 359,
                                'restart_elapsed_ms': 359999}),
    }
    for ident, (field, value) in changes.items():
        candidate = copy.deepcopy(control)
        candidate[field] = value
        if ident == 'MSG-05-N03':
            candidate['signing_key_id'] = 'signing-2'
        require(fixtures[ident]['input']['input'] == candidate,
                'MSG-05 isolated scenario: ' + ident)
        expected = ({'verdict': 'ACCEPT',
                     'output': {'fresh': True, 'accepted': 1, 'rejected': 1},
                     'effects': {}} if ident == 'MSG-05-N04' else
                    {'verdict': 'REJECT', 'output': {}, 'effects': {}})
        require(fixtures[ident]['expected'] == expected,
                'MSG-05 scoped outcome: ' + ident)
    require(control['created'] <= control['trusted_now_unix'] + 30
            and control['trusted_now_unix'] < control['expires'] + 30
            and fixtures['MSG-05-N01']['input']['input']['trusted_now_unix']
            == control['expires'] + 30
            and fixtures['MSG-05-N02']['input']['input']['trusted_now_unix'] + 30
            < control['created'], 'MSG-05 strict timing boundaries')
    return len(IDS)


if __name__ == '__main__':
    print('Verified MSG-05 scoped fixtures:', check())
