"""Check ID-02 authority and canonical-identifier fixtures."""

from current_spec_catalog import ROOT, load, require


IDS = ('ID-02-P', 'ID-02-N01', 'ID-02-N02', 'ID-02-N03')


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'ID-02 fixture identity')
    source = load((root / 'vectors/0.10.0/registry-records.json').read_bytes())
    records = {row['id']: row for row in source['cases']
               if row['operation'] == 'sage.did.validate'}
    web = records['did-web']['input']['did']
    chain = records['did-chain']['input']['did']
    require(records['did-web']['expected']['verdict'] == 'ACCEPT' and
            records['did-chain']['expected']['verdict'] == 'ACCEPT',
            'independent canonical DIDs')
    primary = {'registry_id': 'web:agents.example.com',
               'agent_id': 'alice', 'did': web}
    other = {'registry_id': 'web:other.example.com',
             'agent_id': 'alice',
             'did': 'did:sage:web:other.example.com:alice'}
    for ident, right, verdict, same in (
            ('ID-02-P', primary, 'ACCEPT', True),
            ('ID-02-N01', other, 'REJECT', False)):
        require(fixtures[ident]['input'] == {
                'operation': 'sage.registry.identity.require-same',
                'input': {'left': primary, 'right': right}} and
                fixtures[ident]['expected'] == {
                    'verdict': verdict, 'output': {'same_identity': same},
                    'effects': {}},
                'ID-02 registry authority comparison: ' + ident)
    for ident, name in (('ID-02-N02', 'did-alias'),
                        ('ID-02-N03', 'did-upper-address')):
        candidate = records[name]['input']['did']
        require(records[name]['expected']['verdict'] == 'REJECT' and
                fixtures[ident]['input'] == {
                    'operation': 'sage.did.boundary.pair', 'input': {
                        'control': {'did': chain},
                        'candidate': {'did': candidate}}} and
                fixtures[ident]['expected'] == {
                    'verdict': 'ACCEPT',
                    'output': {'control_verdict': 'ACCEPT',
                               'candidate_verdict': 'REJECT'}, 'effects': {}},
                'ID-02 valid-control canonical boundary: ' + ident)
    require(primary['did'] != other['did'] and
            primary['agent_id'] == other['agent_id'] and
            primary['registry_id'] != other['registry_id'] and
            records['did-alias']['input']['did'].startswith('did:sage:eth:') and
            '0xABAB' in records['did-upper-address']['input']['did'],
            'distinct registry and canonical collisions')
    spec = (root / 'verification/0.10.0/snapshot/spec/06-did-sage.md').read_text()
    require('Two registries MUST NOT' in spec and
            'agent-id` is unique within that registry' in spec and
            'There are no aliases' in spec and
            'An identifier that is not in normal form MUST be rejected' in spec,
            'pinned identity and normalisation rules')
    return len(IDS)


if __name__ == '__main__':
    print('Verified ID-02 identity fixtures:', check())
