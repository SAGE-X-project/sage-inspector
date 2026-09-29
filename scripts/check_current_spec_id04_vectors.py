"""Check ID-04 lifecycle requests against audited records and transition rules."""

from current_spec_catalog import ROOT, load, require


IDS = ('ID-04-P', 'ID-04-N01', 'ID-04-N02', 'ID-04-N03')


def check(root=ROOT):
    source = load((root / 'vectors/0.10.0/registry-records.json').read_bytes())
    records = {row['id']: row for row in source['cases']}
    scenario = load((root / 'vectors/0.10.0/registry-scenarios/'
                     'registry-mutations.json').read_bytes())
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    base = dict(records['authenticate-valid']['input']['record'],
                version='2')
    new_key = next(key for key in
                   records['authenticate-historical-False']['input']['record']['keys']
                   if key['name'] == 'signing-2')
    old_key = next(key for key in base['keys'] if key['name'] == 'signing-1')
    did = base['id']
    require(base['state'] == 'active' and base['controller'] == 'test-controller'
            and base['version'] == '2' and
            new_key['proof']['signer'] == did + '#signing-2' and
            old_key['name'] != new_key['name'] and
            new_key['key'] != old_key['key'],
            'ID-04 independently audited active record and new key')
    positive = {'record': base, 'operation': 'add-key',
                'actor': base['controller'], 'expected_version': '2',
                'proposed_did': did, 'key': new_key}
    variants = {
        'ID-04-P': positive,
        'ID-04-N01': dict(positive, actor='other-controller'),
        'ID-04-N02': dict(positive,
                        proposed_did='did:sage:web:agents.example.com:bob'),
        'ID-04-N03': dict(positive, key=old_key),
    }
    for ident, request in variants.items():
        expected = ({'verdict': 'ACCEPT',
                     'output': {'version': '3', 'state': 'active'},
                     'effects': {'mutations': 1}}
                    if ident == 'ID-04-P' else
                    {'verdict': 'REJECT', 'output': {},
                     'effects': {'mutations': 0}})
        require(fixtures[ident]['id'] == ident and
                fixtures[ident]['track'] == 'runtime' and
                fixtures[ident]['input'] == {
                    'operation': 'sage.registry.lifecycle.apply',
                    'input': request} and
                fixtures[ident]['expected'] == expected,
                'ID-04 isolated lifecycle condition: ' + ident)
    require(scenario['steps'][1]['input']['authorized'] is False and
            scenario['steps'][1]['expected']['verdict'] == 'REJECT' and
            scenario['steps'][1]['effects']['mutations'] == 0 and
            scenario['steps'][5]['input']['authorized'] is True and
            scenario['steps'][5]['expected']['verdict'] == 'ACCEPT' and
            scenario['steps'][5]['effects']['mutations'] == 1 and
            scenario['steps'][9]['expected']['output']['state'] == 'deactivated',
            'independent authorization, version, and terminal-state model')
    spec = (root / 'verification/0.10.0/snapshot/spec/09-registry.md').read_text()
    require('each successful atomic mutation increments' in spec and
            'Mutations require the authenticated controller' in spec and
            'Wrong' in spec and 'without changing anything' in spec and
            'new immutable name/material' in spec and
            'The identifier is never reassigned' in spec,
            'pinned lifecycle rules')
    return len(IDS)


if __name__ == '__main__':
    print('Verified ID-04 lifecycle fixtures:', check())
