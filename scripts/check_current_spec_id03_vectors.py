"""Check ID-03 named-key authentication fixtures against independent records."""

from current_spec_catalog import ROOT, load, require


SOURCE_IDS = {
    'ID-03-P': 'authenticate-valid',
    'ID-03-N01': 'authenticate-unknown-key',
    'ID-03-N02': 'authenticate-historical-False',
    'ID-03-N03': 'authenticate-historical-True',
    'ID-03-N04': 'authenticate-algorithm',
    'ID-03-N05': 'authenticate-other-sender',
}
IDS = tuple(SOURCE_IDS)


def check(root=ROOT):
    source = load((root / 'vectors/0.10.0/registry-records.json').read_bytes())
    records = {row['id']: row for row in source['cases']
               if row['operation'] == 'sage.registry.authenticate'}
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    for ident, source_id in SOURCE_IDS.items():
        fixture, record = fixtures[ident], records[source_id]
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input'] == {'operation': record['operation'],
                                     'input': record['input']} and
                fixture['expected'] == dict(record['expected'], effects={}),
                'ID-03 independently audited record: ' + ident)
    positive = records['authenticate-valid']['input']
    unknown = records['authenticate-unknown-key']['input']
    revoked = records['authenticate-historical-False']['input']
    expired = records['authenticate-historical-True']['input']
    algorithm = records['authenticate-algorithm']['input']
    sender = records['authenticate-other-sender']['input']
    key = positive['keyid']
    require(positive['record']['state'] == 'active' and
            positive['sender'] == positive['expected_peer'] ==
            positive['record']['id'] and
            key == positive['record']['id'] + '#signing-1' and
            records['authenticate-valid']['expected']['verdict'] == 'ACCEPT',
            'ID-03 accepted named-key control')
    require(unknown['keyid'] == positive['record']['id'] + '#missing' and
            unknown['record'] == positive['record'] and
            unknown['sender'] == positive['sender'],
            'ID-03 absent key changes only key reference')
    for candidate, state, expiry in ((revoked, 'revoked', None),
                                     (expired, 'accepted', positive['now'])):
        selected = next(row for row in candidate['record']['keys']
                        if row['name'] == 'signing-1')
        require(candidate['keyid'] == key and selected['state'] == state and
                selected.get('expires') == expiry and
                any(row['name'] == 'signing-2' and row['state'] == 'accepted'
                    for row in candidate['record']['keys']) and
                candidate['sender'] == positive['sender'],
                'ID-03 no fallback to another signing key')
    require(algorithm['record'] == positive['record'] and
            algorithm['keyid'] == key and
            algorithm['alg'] != positive['alg'] and
            sender['record'] == positive['record'] and
            sender['keyid'] == key and
            sender['sender'] != positive['sender'] and
            sender['expected_peer'] == positive['expected_peer'],
            'ID-03 algorithm and sender binding')
    require(all(records[source_id]['expected']['verdict'] == 'REJECT'
                for ident, source_id in SOURCE_IDS.items() if ident != 'ID-03-P'),
            'ID-03 negative independent verdicts')
    spec = (root / 'verification/0.10.0/snapshot/spec/06-did-sage.md').read_text()
    require('finds the key with that name and rejects if there is none' in spec and
            'is revoked, or has expired' in spec and
            'uses only the algorithm of that selected key' in spec and
            'MUST NOT try' in spec,
            'pinned exact-key verification rules')
    return len(IDS)


if __name__ == '__main__':
    print('Verified ID-03 named-key fixtures:', check())
