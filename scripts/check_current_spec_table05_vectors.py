"""Independently audit registered, reserved, and unknown registry kinds."""

import copy
import ipaddress
import re

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/table05-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('TABLE-05-P', 'TABLE-05-N01', 'TABLE-05-N02')
HASHES = {
    'spec/11-registries.md': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
    'spec/06-did-sage.md': '5791cc368111216a6539f7c423811abeb9821f9741e0c5d6ce177d5100b0b059',
    'spec/09-registry.md': '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02',
}
ADDRESS = '0xc7ecf7ad6ee71cb0d94f0eb00f46f1ddf432a808'
BINDING = {
    'kind': 'eip155', 'chain_id': '11155111', 'registry_address': ADDRESS,
    'deployed_code_hash': '0x' + '11' * 32,
    'upgrade_policy': 'pinned-code-hash',
    'abi_mapping': 'sections-1-through-5',
    'operator_scopes': 'controller-authorized',
    'transaction_authorization': 'authenticated-controller',
    'finalized_node_readiness': 'required',
    'costs_latency': 'measured-for-deployment',
}
POSITIVE = {
    'protocol_version': '0.10.0', 'kind': 'eip155',
    'locator': '11155111:' + ADDRESS,
    'policy': {'allow_eip155': True, 'allow_web': False,
               'require_blockchain': True},
    'binding': BINDING,
}


def selected(inp):
    if type(inp) is not dict or set(inp) != {
            'protocol_version', 'kind', 'locator', 'policy', 'binding'}:
        return None
    if inp['protocol_version'] != '0.10.0':
        return None
    policy, binding = inp['policy'], inp['binding']
    if (type(policy) is not dict or set(policy) != {
            'allow_eip155', 'allow_web', 'require_blockchain'} or
            any(type(value) is not bool for value in policy.values()) or
            type(binding) is not dict or type(inp['locator']) is not str):
        return None
    if inp['kind'] == 'eip155':
        if not policy['allow_eip155']:
            return None
        match = re.fullmatch(r'([1-9][0-9]{0,31}):(0x[0-9a-f]{40})',
                             inp['locator'])
        if match is None or set(binding) != set(BINDING):
            return None
        if (binding['kind'] != 'eip155' or binding['chain_id'] != match[1] or
                binding['registry_address'] != match[2] or
                type(binding['deployed_code_hash']) is not str or
                re.fullmatch(r'0x[0-9a-f]{64}', binding['deployed_code_hash']) is None or
                any(type(binding[field]) is not str or not binding[field]
                    for field in set(BINDING) - {
                        'kind', 'chain_id', 'registry_address', 'deployed_code_hash'})):
            return None
        return 'eip155'
    if inp['kind'] == 'web':
        domain = inp['locator']
        if not policy['allow_web'] or policy['require_blockchain']:
            return None
        try:
            ipaddress.ip_address(domain)
            return None
        except ValueError:
            pass
        if (len(domain.encode()) > 64 or not all(
                re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                for label in domain.split('.')) or
                set(binding) != {'kind', 'configured_origin',
                                 'approved_destinations', 'operator_policy',
                                 'fresh_reads'} or
                binding['kind'] != 'web' or
                binding['configured_origin'] != 'https://' + domain or
                binding['approved_destinations'] != [domain] or
                binding['operator_policy'] != 'authenticated-atomic' or
                binding['fresh_reads'] is not True):
            return None
        return 'web'
    return None


def check(root=ROOT):
    data = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(data['schema_version'] == 1 and data['spec_revision'] == SPEC and
            data['source_sha256'] == HASHES and
            all(manifest['source_sha256'][path] == digest for path, digest in HASHES.items()) and
            data['scope'] == 'synthetic kind and descriptor selection; no contract, ABI, chain finality, TLS, or deployment attestation' and
            tuple(row['id'] for row in data['cases']) == IDS,
            'pinned TABLE-05 sources and bounded cases')
    good, reserved, unknown = [row['input'] for row in data['cases']]
    require(good == POSITIVE and selected(good) == 'eip155' and
            reserved == dict(good, kind='solana') and
            unknown == dict(good, kind='unknownchain'),
            'exact supported, reserved, and unregistered kind scenarios')
    for index, row in enumerate(data['cases']):
        ident = row['id']
        expected = {'verdict': 'ACCEPT' if index == 0 else 'REJECT',
                    'output': {'selected_kind': 'eip155'} if index == 0 else {},
                    'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(selected(row['input']) == ('eip155' if index == 0 else None) and
                row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.registry.kind.select',
                                      'input': row['input']}, 'expected': expected},
                'TABLE-05 case contract: ' + ident)
    web = {
        'protocol_version': '0.10.0', 'kind': 'web',
        'locator': 'agents.example.com',
        'policy': {'allow_eip155': True, 'allow_web': True,
                   'require_blockchain': False},
        'binding': {'kind': 'web',
                    'configured_origin': 'https://agents.example.com',
                    'approved_destinations': ['agents.example.com'],
                    'operator_policy': 'authenticated-atomic',
                    'fresh_reads': True},
    }
    controls = [('configured-web', web, 'web')]
    for name, base, path, value in (
        ('missing-code-hash', good, ('binding', 'deployed_code_hash'), None),
        ('missing-abi-map', good, ('binding', 'abi_mapping'), None),
        ('chain-mismatch', good, ('binding', 'chain_id'), '1'),
        ('leading-zero-chain', good, ('locator',), '011155111:' + ADDRESS),
        ('uppercase-address', good, ('locator',), '11155111:' + ADDRESS.upper()),
        ('wrong-binding-kind', good, ('binding', 'kind'), 'web'),
        ('unapproved-eip155', good, ('policy', 'allow_eip155'), False),
        ('web-blockchain-required', web, ('policy', 'require_blockchain'), True),
        ('web-no-origin', web, ('binding', 'configured_origin'), None),
        ('web-unapproved-destination', web, ('binding', 'approved_destinations'), []),
        ('reserved-with-descriptor', good, ('kind',), 'solana'),
        ('unknown-case-variant', good, ('kind',), 'EIP155'),
    ):
        changed = copy.deepcopy(base)
        node = changed
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value
        controls.append((name, changed, None))
    require(all(selected(inp) == expected for _, inp, expected in controls),
            'independent locator, configuration, reserved, and web controls')
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(all(any(binding['id'] == ident and binding['track'] == 'runtime' and
                    binding['coverage'] == 'partial' and
                    binding['fixture_sha256'] == sha((root / 'vectors/0.10.0/current-spec' /
                                                     (ident + '.json')).read_bytes())
                    for binding in bindings['bindings']) for ident in IDS),
            'partial runtime case bindings')
    return len(IDS), len(controls)


if __name__ == '__main__':
    print(check())
