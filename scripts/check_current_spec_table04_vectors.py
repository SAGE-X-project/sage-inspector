"""Independently audit exact domain-label bytes and construction roles."""

import copy
import re

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/table04-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('TABLE-04-P', 'TABLE-04-N01', 'TABLE-04-N02', 'TABLE-04-N03')
HASHES = {
    'spec/11-registries.md': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
    'spec/04-hpke.md': '1420818451ce8363a16e391647dbaca8ec2f06efa56b6507027a4e17f399fdd6',
    'spec/05-session.md': '8a45b8bdd3b6bfc399a94c420b2161b8f16db5c6b29ed2e85584a6282b17cce5',
    'spec/07-a2a.md': '5ded622fdaf67342d5c6b4327da0f5787bfe9df2dc58b233cdfb500ffc96b042',
    'spec/08-transport.md': '87bb1adc1aae4883e13f8ba52a7c86153c71efb621ffc50458f7e2aa57db3eeb',
    'spec/09-registry.md': '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02',
    'profiles/agent-mcp-security.md': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
}
DOMAINS = {
    'registry_pop': b'sage-pop-0.10.0',
    'registry_claim': b'sage-claim-0.10.0\x00',
    'card_proof': b'sage-card-0.10.0\x00',
    'guard_intent': b'sage-execution-intent|0.10.0\x00',
    'guard_result': b'sage-tool-result|0.10.0\x00',
    'wire_request': b'sage-wire-request|0.10.0\n',
    'wire_response': b'sage-wire-response|0.10.0\n',
    'hpke_combiner': b'sage-hpke-combiner|0.10.0',
    'hpke_ack': b'sage-hpke-ack|0.10.0',
    'hpke_info': b'sage-hpke-info|0.10.0\n',
    'hpke_export': b'sage-hpke-export|0.10.0\n',
    'hpke_complete': b'sage-hpke-complete|0.10.0\n',
    'record_aad': b'sage-record|0.10.0',
    'session_id': b'sage-session|0.10.0',
    'session_c2s': b'sage-c2s-key|0.10.0',
    'session_s2c': b'sage-s2c-key|0.10.0',
    'original_capture': b'sage-original|0.10.0\x00',
    'policy_commitment': b'sage-policy|0.10.0\x00',
}


def matches(inp):
    if type(inp) is not dict or set(inp) != {'domains'} or type(inp['domains']) is not dict:
        return False
    domains = inp['domains']
    if set(domains) != set(DOMAINS):
        return False
    for name, expected in DOMAINS.items():
        value = domains[name]
        if (type(value) is not str or re.fullmatch('(?:[0-9a-f]{2})+', value) is None
                or bytes.fromhex(value) != expected):
            return False
    return True


def check(root=ROOT):
    data = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(data['schema_version'] == 1 and data['spec_revision'] == SPEC and
            data['source_sha256'] == HASHES and
            all(manifest['source_sha256'][path] == digest for path, digest in HASHES.items()) and
            data['scope'] == 'synthetic domain-byte dispatch; no signatures, HKDF derivation, deployed cryptographic interoperability, or release claim' and
            tuple(row['id'] for row in data['cases']) == IDS and
            len(DOMAINS) == 18 and len(set(DOMAINS.values())) == 18,
            'pinned TABLE-04 source identities and distinct exact domains')
    good, legacy, missing_lf, wrong_hkdf = [row['input'] for row in data['cases']]
    require(good == {'domains': {name: value.hex() for name, value in DOMAINS.items()}} and
            matches(good), 'all eighteen exact domain prefixes')
    require(legacy == {'domains': dict(good['domains'],
                                       hpke_info=b'sage/hpke-info|v1\n'.hex())} and
            missing_lf == {'domains': dict(good['domains'],
                                           wire_request=b'sage-wire-request|0.10.0'.hex())} and
            wrong_hkdf == {'domains': dict(good['domains'],
                                           hpke_combiner=good['domains']['hpke_ack'])},
            'isolated obsolete label, omitted LF, and HKDF role defects')
    for index, row in enumerate(data['cases']):
        ident = row['id']
        expected = {'verdict': 'ACCEPT' if index == 0 else 'REJECT',
                    'output': {'matched_domains': 18} if index == 0 else {},
                    'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(matches(row['input']) == (index == 0) and row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.domain.registry.check',
                                      'input': row['input']}, 'expected': expected},
                'TABLE-04 case contract: ' + ident)
    controls = []
    for name, role, mutation in (
        ('omitted-intent-nul', 'guard_intent', b'sage-execution-intent|0.10.0'),
        ('omitted-card-nul', 'card_proof', b'sage-card-0.10.0'),
        ('omitted-hpke-export-lf', 'hpke_export', b'sage-hpke-export|0.10.0'),
        ('wrong-hpke-complete-delimiter', 'hpke_complete',
         b'sage-hpke-complete|0.10.0\x00'),
        ('old-pop-label', 'registry_pop', b'sage-pop-v1'),
        ('old-session-label', 'session_id', b'sage-session-keys-v1'),
        ('swapped-wire-direction', 'wire_request', DOMAINS['wire_response']),
        ('case-variant', 'hpke_ack', b'SAGE-hpke-ack|0.10.0'),
        ('extra-hkdf-nul', 'hpke_combiner', b'sage-hpke-combiner|0.10.0\x00'),
        ('omitted-policy-nul', 'policy_commitment', b'sage-policy|0.10.0'),
    ):
        changed = copy.deepcopy(good)
        changed['domains'][role] = mutation.hex()
        controls.append((name, changed))
    extra = copy.deepcopy(good)
    extra['domains']['unassigned'] = b'sage-new|0.10.0'.hex()
    controls.append(('unassigned-domain', extra))
    uppercase = copy.deepcopy(good)
    uppercase['domains']['guard_result'] = good['domains']['guard_result'].upper()
    controls.append(('noncanonical-hex', uppercase))
    require(all(not matches(inp) for _, inp in controls),
            'independent delimiter, role, legacy, and encoding controls')
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(all(any(binding['id'] == ident and binding['track'] == 'runtime' and
                    binding['coverage'] == 'partial' and
                    binding['fixture_sha256'] == sha((root / 'vectors/0.10.0/current-spec' /
                                                     (ident + '.json')).read_bytes())
                    for binding in bindings['bindings']) for ident in IDS),
            'partial runtime case bindings')
    return len(IDS), len(DOMAINS), len(controls)


if __name__ == '__main__':
    print(check())
