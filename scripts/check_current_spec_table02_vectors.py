"""Independently audit exact signature algorithm names and roles."""

import copy

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/table02-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
REGISTRIES_SHA = 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4'
CRYPTO_SHA = 'fe9fd00066b259b99a63e5adab7db739757e3ad2597ccc71e2019fa34319faec'
IDS = ('TABLE-02-P', 'TABLE-02-N01', 'TABLE-02-N02')
SUITES = [
    {'alg': 'ed25519', 'key_type': 'Ed25519', 'digest': 'none',
     'signature_bytes': 64, 'encoding': 'R-S', 'status': 'mandatory'},
    {'alg': 'sage-secp256k1-keccak256', 'key_type': 'secp256k1',
     'digest': 'Keccak-256', 'signature_bytes': 65,
     'encoding': 'r-s-v-low-s', 'status': 'optional'},
    {'alg': 'ecdsa-p256-sha256', 'key_type': 'P-256',
     'digest': 'SHA-256', 'signature_bytes': 64,
     'encoding': 'r-s-low-s', 'status': 'optional'},
]


def selected(inp):
    if inp['registered_suites'] != SUITES:
        return None
    support = inp['implementation_support']
    names = {row['alg'] for row in SUITES}
    if (set(support) != names or not all(type(value) is bool for value in support.values())
            or support['ed25519'] is not True):
        return None
    request = inp['request']
    if (set(request) != {'alg', 'key_type', 'digest', 'signature_bytes',
                        'encoding', 'jose_alias', 'usage', 'wire_scope'} or
            request['usage'] != 'message-signature' or
            request['wire_scope'] != 'external' or
            request['jose_alias'] is not None):
        return None
    suite = next((row for row in SUITES if row['alg'] == request['alg']), None)
    if suite is None or support[suite['alg']] is not True:
        return None
    if any(request[field] != suite[field] for field in
           ('key_type', 'digest', 'signature_bytes', 'encoding')):
        return None
    return suite


def check(root=ROOT):
    data = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(data['schema_version'] == 1 and data['spec_revision'] == SPEC and
            data['registries_sha256'] == REGISTRIES_SHA and
            data['crypto_sha256'] == CRYPTO_SHA and
            manifest['source_sha256']['spec/11-registries.md'] == REGISTRIES_SHA and
            manifest['source_sha256']['spec/01-crypto.md'] == CRYPTO_SHA and
            data['scope'] == 'synthetic algorithm dispatch; no signature generation, verification, or deployed optional-suite claim' and
            tuple(row['id'] for row in data['cases']) == IDS,
            'pinned TABLE-02 sources and bounded cases')
    good = data['cases'][0]['input']
    require(good['registered_suites'] == SUITES and
            good['implementation_support'] == {
                'ed25519': True, 'sage-secp256k1-keccak256': True,
                'ecdsa-p256-sha256': False} and
            good['request'] == {
                'alg': 'sage-secp256k1-keccak256', 'key_type': 'secp256k1',
                'digest': 'Keccak-256', 'signature_bytes': 65,
                'encoding': 'r-s-v-low-s', 'jose_alias': None,
                'usage': 'message-signature', 'wire_scope': 'external'} and
            selected(good) == SUITES[1],
            'exact SAGE-local Keccak suite and mandatory Ed25519 support')
    for index, row in enumerate(data['cases']):
        ident = row['id']
        verdict = 'ACCEPT' if index == 0 else 'REJECT'
        expected = {'verdict': verdict,
                    'output': {'selected_suite': SUITES[1]} if index == 0 else {},
                    'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require((selected(row['input']) is not None) == (index == 0) and
                row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.crypto.signature.suite.select',
                                      'input': row['input']},
                            'expected': expected},
                'TABLE-02 case contract: ' + ident)
    legacy, jose = [row['input'] for row in data['cases'][1:]]
    require(legacy == dict(good, request=dict(good['request'], alg='es256k')) and
            jose == dict(good, request=dict(good['request'], jose_alias='ES256K')),
            'isolated legacy and JOSE alias defects')
    controls = []
    ed = copy.deepcopy(good)
    ed['request'].update(alg='ed25519', key_type='Ed25519', digest='none',
                         signature_bytes=64, encoding='R-S')
    controls.append(('mandatory-ed25519', ed, SUITES[0]))
    disabled = copy.deepcopy(good)
    disabled['implementation_support']['sage-secp256k1-keccak256'] = False
    controls.append(('optional-no-fallback', disabled, None))
    p256 = copy.deepcopy(good)
    p256['request'].update(alg='ecdsa-p256-sha256', key_type='P-256',
                           digest='SHA-256', signature_bytes=64,
                           encoding='r-s-low-s')
    controls.append(('p256-disabled', p256, None))
    enabled = copy.deepcopy(p256)
    enabled['implementation_support']['ecdsa-p256-sha256'] = True
    controls.append(('p256-enabled', enabled, SUITES[2]))
    for name, field, value in (
        ('x25519-signature', 'alg', 'x25519'),
        ('rsa', 'alg', 'rsa-pss-sha256'),
        ('sha3-not-keccak', 'digest', 'SHA3-256'),
        ('sha256-not-keccak', 'digest', 'SHA-256'),
        ('case-variant', 'alg', 'Ed25519'),
        ('wrong-signature-length', 'signature_bytes', 64),
        ('wrong-key-type', 'key_type', 'X25519'),
        ('private-external', 'alg', 'x-local-signature'),
    ):
        changed = copy.deepcopy(good)
        changed['request'][field] = value
        controls.append((name, changed, None))
    require(all(selected(inp) == expected for _, inp, expected in controls),
            'independent exact-name, digest, role, and optional-suite controls')
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
