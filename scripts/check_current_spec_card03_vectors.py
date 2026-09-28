"""Check isolated Agent Card freshness and registry-state fixtures."""

from current_spec_catalog import ROOT, load, require
from check_current_spec_jcs_exclusion_vectors import verify_card


IDS = ('CARD-03-P', 'CARD-03-N01', 'CARD-03-N02',
       'CARD-03-N03', 'CARD-03-N04')


def check(root=ROOT):
    source = load((root / 'vectors/0.10.0/registry-records.json').read_bytes())
    records = {row['id']: row for row in source['cases']}
    control = records['card-valid']['input']
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    card = load(bytes.fromhex(control['card_hex']))
    verify_card(card, control['record'])
    require(fixtures['CARD-03-P']['input'] == {
                'operation': 'sage.card.verify', 'input': control} and
            fixtures['CARD-03-P']['expected'] ==
                dict(records['card-valid']['expected'], effects={}),
            'CARD-03 independently signed control')
    for ident in IDS:
        fixture = fixtures[ident]
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] == 'sage.card.verify' and
                fixture['input']['input']['card_hex'] == control['card_hex'],
                'CARD-03 unchanged signed card: ' + ident)
        if ident != 'CARD-03-P':
            require(fixture['expected'] == {
                        'verdict': 'REJECT', 'output': {}, 'effects': {}},
                    'CARD-03 fail-closed verdict: ' + ident)
    expired = fixtures['CARD-03-N01']['input']['input']
    require(expired == dict(control, now=card['expires']) and
            expired['now'] == records['card-expired']['input']['now'] and
            card['issued'] <= control['now'] < card['expires'],
            'CARD-03 exact expiry boundary')
    version = fixtures['CARD-03-N02']['input']['input']
    require(version['record'] == dict(control['record'], version='2') and
            all(version[key] == control[key] for key in control
                if key != 'record') and
            card['recordVersion'] == control['record']['version'] == '1',
            'CARD-03 current record version mismatch')
    inactive = fixtures['CARD-03-N03']['input']['input']
    require(inactive['record'] == dict(control['record'], state='deactivated') and
            all(inactive[key] == control[key] for key in control
                if key != 'record') and control['record']['state'] == 'active',
            'CARD-03 deactivated registry record')
    service = fixtures['CARD-03-N04']['input']['input']
    expected_services = [dict(control['record']['services'][0],
                              uri='https://agents.example.com/new-api')]
    require(service['record'] == dict(control['record'],
                                      services=expected_services) and
            all(service[key] == control[key] for key in control
                if key != 'record') and
            card['services'] == control['record']['services'] !=
                expected_services,
            'CARD-03 stale service endpoint after registry update')
    spec = (root / 'verification/0.10.0/snapshot/spec/07-a2a.md').read_text()
    require('Resolve the authoritative registry with chapter 09 freshness rules.'
            in spec and 'Require exact record-version equality and identical'
            in spec and 'A changed registry version' in spec,
            'pinned CARD-03 registry comparison rules')
    return len(IDS)


if __name__ == '__main__':
    print('Verified CARD-03 registry-state fixtures:', check())
