"""Prepare bounded eip155 deployment and claim review fixtures."""

import base64
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
ADDRESS = '0x' + 'ab' * 20
REGISTRY = 'eip155:1:' + ADDRESS
CONTROLLER = '0x' + 'cd' * 20
CODE_HASH = 'a1' * 32
IDS = ('REG-06-P', 'REG-06-N01', 'REG-06-N02', 'REG-06-N03',
       'REG-06-N04')


def deployment():
    return {
        'chain_id': '1', 'registry_address': ADDRESS,
        'deployed_code_hash': CODE_HASH,
        'upgrade_policy': {'kind': 'immutable', 'authorized_upgrades': False},
        'abi_mapping': {'sections': ['1', '2', '3', '4', '5'],
                        'authenticated_reads': True,
                        'authenticated_writes': True},
        'operator_scopes': {'register': 'controller',
                            'mutate': 'controller-or-delegate'},
        'transaction_authorization': {'controller_account': CONTROLLER,
                                      'chain_id': '1'},
        'finalized_node': {'identity': 'pinned-node', 'ready': True,
                           'finality_policy': 'confirmed-finalized'},
        'measured_cost_latency': {'claim_gas': 100000,
                                  'finalized_read_ms': 1200},
    }


def claim():
    return {
        'registryId': REGISTRY, 'agentId': 'alice',
        'controller': CONTROLLER,
        'keys': [{'name': 'signing-1', 'alg': 'ed25519',
                  'material': '03' * 32}],
        'services': [],
        'salt': base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('='),
    }


def main():
    good = deployment()
    unknown = json.loads(json.dumps(good))
    unknown['registry_address'] = '0x' + 'ef' * 20
    changed = json.loads(json.dumps(good))
    changed['deployed_code_hash'] = 'b2' * 32
    missing = json.loads(json.dumps(good))
    missing['abi_mapping']['sections'].remove('4')
    cases = [
        ('REG-06-P', good, True, True, 'pinned complete deployment'),
        ('REG-06-N01', unknown, True, True, 'unknown registry address'),
        ('REG-06-N02', changed, True, True, 'deployed code hash changed'),
        ('REG-06-N03', missing, True, True, 'authenticated ABI section absent'),
        ('REG-06-N04', good, False, True, 'record and keys read from different finalized blocks'),
    ]
    rows = []
    for ident, candidate, consistent, finalized, purpose in cases:
        observation = {'record_block_hash': '11' * 32,
                       'keys_block_hash': ('11' if consistent else '22') * 32,
                       'finalized': finalized, 'source': 'pinned-node'}
        inp = {'trusted_configuration': good, 'candidate': candidate,
               'observation': observation}
        expected = {'verdict': 'ACCEPT' if ident == 'REG-06-P' else 'REJECT',
                    'output': {}, 'effects': {}}
        rows.append({'id': ident, 'purpose': purpose, 'input': inp,
                     'expected': expected})
    claim_value = claim()
    canonical = json.dumps(claim_value, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False).encode()
    preimage = b'sage-claim-0.10.0\0' + canonical
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02',
             'scope': 'synthetic deployment and finalized reads; no deployed contract or transaction',
             'cases': rows,
             'claim_control': {'claim': claim_value,
                               'canonical_utf8_hex': canonical.hex(),
                               'commitment_sha256': hashlib.sha256(preimage).hexdigest(),
                               'commit_account': CONTROLLER,
                               'commit_block': 100,
                               'valid_reveal_block': 101,
                               'last_reveal_block': 356,
                               'late_reveal_block': 357,
                               'other_account': '0x' + 'ef' * 20,
                               'activation_separate': True}}
    output = ROOT / 'vectors/0.10.0/reg06-scenarios.json'
    output.write_text(json.dumps(suite, indent=2) + '\n')
    for row in rows:
        for track in ('runtime', 'deployment_review'):
            fixture = {
                'schema_version': 1, 'spec_revision': SPEC,
                'id': row['id'], 'track': track,
                'input': ({'operation': 'sage.registry.eip155.binding.check',
                           'input': row['input']} if track == 'runtime' else
                          {'review_subject': 'pinned eip155 deployment',
                           'required': ['chain_id', 'registry_address',
                                        'deployed_code_hash', 'upgrade_policy',
                                        'abi_mapping', 'operator_scopes',
                                        'transaction_authorization',
                                        'finalized_node', 'measured_cost_latency'],
                           'trusted_configuration': row['input']['trusted_configuration'],
                           'candidate': row['input']['candidate'],
                           'observation': row['input']['observation']}),
                'expected': row['expected']}
            relative = ('vectors/0.10.0/current-spec/' + row['id'] +
                        '-' + track + '.json')
            (ROOT / relative).write_text(json.dumps(fixture, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    for ident in IDS:
        for track in ('runtime', 'deployment_review'):
            relative = ('vectors/0.10.0/current-spec/' + ident +
                        '-' + track + '.json')
            bindings['bindings'].append({
                'id': ident, 'track': track, 'fixture': relative,
                'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')
    print('Generated five REG-06 cases, ten track fixtures, and one claim control')


if __name__ == '__main__':
    main()
