"""Audit reserved Solana fixtures without treating legacy parsing as resolution."""

from current_spec_catalog import ROOT, load, require


SOURCE = 'vectors/0.10.0/reg07-scenarios.json'
IDS = ('REG-07-P', 'REG-07-N01')
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CHAPTER_SHA = '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC
            and suite['source_sha256'] == CHAPTER_SHA
            and manifest['source_sha256']['spec/09-registry.md'] == CHAPTER_SHA
            and tuple(row['id'] for row in suite['cases']) == IDS,
            'pinned REG-07 case inventory and source')
    positive, negative = suite['cases']
    did = positive['input']['did']
    require(did == negative['input']['did'] ==
            'did:sage:solana:chain:alice'
            and positive['operation'] == 'sage.registry.resolve'
            and negative['operation'] == 'sage.registry.profile.admit'
            and negative['input']['claim_conformance'] is True
            and negative['input']['record']['id'] == did
            and positive['input']['protocol_version'] ==
                negative['input']['protocol_version'] == '0.10.0',
            'reserved kind in resolution and conformant-record admission')
    expected = {'verdict': 'REJECT',
                'output': {'code': 'id.unknown-kind'}, 'effects': {}}
    for row in suite['cases']:
        ident = row['id']
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(row['expected'] == expected and fixture == {
                    'schema_version': 1, 'spec_revision': SPEC,
                    'id': ident, 'track': 'runtime',
                    'input': {'operation': row['operation'],
                              'input': row['input']},
                    'expected': expected},
                'REG-07 exact rejection fixture: ' + ident)
    controls = suite['primitive_controls']
    require(tuple(row['id'] for row in controls) ==
            ('reserved', 'web', 'eip155') and controls[0]['did'] == did
            and controls[1]['did'] == 'did:sage:web:agents.example.com:alice'
            and controls[2]['did'].startswith('did:sage:eip155:1:0x')
            and controls[2]['did'].endswith(':alice')
            and len(controls[2]['did'].split(':')[4]) == 42,
            'separate legacy DID parser controls')
    return len(IDS), len(controls)


if __name__ == '__main__':
    print(check())
