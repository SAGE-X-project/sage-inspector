"""Bind reserved Solana profile cases to current-spec resolver boundaries."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
DID = 'did:sage:solana:chain:alice'
IDS = ('REG-07-P', 'REG-07-N01')


def main():
    rows = [
        {'id': IDS[0], 'purpose': 'reserved kind returns the exact public error',
         'operation': 'sage.registry.resolve',
         'input': {'did': DID, 'protocol_version': '0.10.0'}},
        {'id': IDS[1], 'purpose': 'a Solana record cannot be admitted as conformant',
         'operation': 'sage.registry.profile.admit',
         'input': {'did': DID, 'protocol_version': '0.10.0',
                   'record': {'id': DID, 'state': 'active'},
                   'claim_conformance': True}},
    ]
    for row in rows:
        row['expected'] = {'verdict': 'REJECT',
                           'output': {'code': 'id.unknown-kind'},
                           'effects': {}}
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02',
             'cases': rows,
             'primitive_controls': [
                 {'id': 'reserved', 'did': DID},
                 {'id': 'web', 'did': 'did:sage:web:agents.example.com:alice'},
                 {'id': 'eip155',
                  'did': 'did:sage:eip155:1:0x' + 'ab' * 20 + ':alice'},
             ]}
    (ROOT / 'vectors/0.10.0/reg07-scenarios.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    for row in rows:
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': row['id'], 'track': 'runtime',
                   'input': {'operation': row['operation'],
                             'input': row['input']},
                   'expected': row['expected']}
        (ROOT / 'vectors/0.10.0/current-spec' /
         (row['id'] + '.json')).write_text(json.dumps(fixture, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    for ident in IDS:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')
    print('Generated two REG-07 cases and three primitive controls')


if __name__ == '__main__':
    main()
