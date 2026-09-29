"""Generate bounded registry-kind selection fixtures."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('TABLE-05-P', 'TABLE-05-N01', 'TABLE-05-N02')
ADDRESS = '0xc7ecf7ad6ee71cb0d94f0eb00f46f1ddf432a808'


def main():
    positive = {
        'protocol_version': '0.10.0',
        'kind': 'eip155',
        'locator': '11155111:' + ADDRESS,
        'policy': {'allow_eip155': True, 'allow_web': False,
                   'require_blockchain': True},
        'binding': {
            'kind': 'eip155', 'chain_id': '11155111',
            'registry_address': ADDRESS,
            'deployed_code_hash': '0x' + '11' * 32,
            'upgrade_policy': 'pinned-code-hash',
            'abi_mapping': 'sections-1-through-5',
            'operator_scopes': 'controller-authorized',
            'transaction_authorization': 'authenticated-controller',
            'finalized_node_readiness': 'required',
            'costs_latency': 'measured-for-deployment',
        },
    }
    reserved = copy.deepcopy(positive)
    reserved['kind'] = 'solana'
    unknown = copy.deepcopy(positive)
    unknown['kind'] = 'unknownchain'
    rows = [
        ('TABLE-05-P', positive, 'ACCEPT', 'configured eip155 kind and bounded deployment descriptor'),
        ('TABLE-05-N01', reserved, 'REJECT', 'reserved solana kind advertised as supported'),
        ('TABLE-05-N02', unknown, 'REJECT', 'unregistered kind advertised as supported'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': {'selected_kind': 'eip155'} if verdict == 'ACCEPT' else {},
                    'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'runtime',
                   'input': {'operation': 'sage.registry.kind.select',
                             'input': inp}, 'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': {
                 'spec/11-registries.md': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
                 'spec/06-did-sage.md': '5791cc368111216a6539f7c423811abeb9821f9741e0c5d6ce177d5100b0b059',
                 'spec/09-registry.md': '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02'},
             'scope': 'synthetic kind and descriptor selection; no contract, ABI, chain finality, TLS, or deployment attestation',
             'cases': cases}
    (ROOT / 'vectors/0.10.0/table05-scenarios.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident in IDS:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
