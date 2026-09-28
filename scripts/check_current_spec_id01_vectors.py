"""Check ID-01 DID grammar fixtures and valid-control isolation."""

from current_spec_catalog import ROOT, load, require


IDS = ('ID-01-P', 'ID-01-N01', 'ID-01-N02', 'ID-01-N03',
       'ID-01-N04', 'ID-01-N05')


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'ID-01 fixture identity')
    source = load((root / 'vectors/0.10.0/registry-records.json').read_bytes())
    records = {row['id']: row for row in source['cases']
               if row['operation'] == 'sage.did.validate'}
    control = records['did-web']['input']['did']
    require(records['did-web']['expected']['verdict'] == 'ACCEPT' and
            control == 'did:sage:web:agents.example.com:alice' and
            len(control.encode('ascii')) <= 256,
            'independent canonical DID control')
    require(fixtures['ID-01-P']['input'] == {
            'operation': 'sage.did.validate', 'input': {'did': control}} and
            fixtures['ID-01-P']['expected'] == {'verdict': 'ACCEPT',
                'output': {'valid': True}, 'effects': {}},
            'ID-01 canonical DID fixture')
    candidates = {
        'ID-01-N01': records['did-alias']['input']['did'],
        'ID-01-N02': records['did-percent']['input']['did'],
        'ID-01-N03': records['did-upper-domain']['input']['did'],
        'ID-01-N04': control.rsplit(':', 1)[0] + ':' + 'a' * 230,
    }
    for ident, name in (('ID-01-N01', 'did-alias'),
                        ('ID-01-N02', 'did-percent'),
                        ('ID-01-N03', 'did-upper-domain')):
        require(records[name]['expected']['verdict'] == 'REJECT' and
                candidates[ident] == records[name]['input']['did'],
                'independent malformed DID source: ' + ident)
    require(len(candidates['ID-01-N04'].encode('ascii')) > 256 and
            candidates['ID-01-N04'].startswith(control.rsplit(':', 1)[0] + ':') and
            '%' in candidates['ID-01-N02'] and
            'Agents.example.com' in candidates['ID-01-N03'],
            'DID length, escape, and case boundaries')
    for ident, candidate in candidates.items():
        require(fixtures[ident]['input'] == {
            'operation': 'sage.did.boundary.pair', 'input': {
                'control': {'did': control}, 'candidate': {'did': candidate}}} and
            fixtures[ident]['expected'] == {'verdict': 'ACCEPT',
                'output': {'control_verdict': 'ACCEPT',
                           'candidate_verdict': 'REJECT'}, 'effects': {}},
            'ID-01 valid-control boundary fixture: ' + ident)
    require(fixtures['ID-01-N05']['input'] == {
            'operation': 'sage.did.keyurl.boundary.pair', 'input': {
                'control': {'key_url': control + '#key-1'},
                'candidate': {'key_url': control}}} and
            fixtures['ID-01-N05']['expected'] == {'verdict': 'ACCEPT',
                'output': {'control_verdict': 'ACCEPT',
                           'candidate_verdict': 'REJECT'}, 'effects': {}},
            'ID-01 missing key fragment fixture')
    spec = (root / 'verification/0.10.0/snapshot/spec/06-did-sage.md').read_text()
    require('A DID MUST be at most 256 ASCII bytes' in spec and
            'did-url      = did-sage "#" key-id' in spec and
            'no percent-encoding is permitted' in spec and
            'There are no aliases' in spec,
            'pinned DID grammar, length, and normalization rules')
    return len(IDS)


if __name__ == '__main__':
    print('Verified ID-01 DID grammar fixtures:', check())
