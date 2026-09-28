"""Independently audit exact registry key and DID JWK encoding cases."""

import base64
import copy
import re

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/table03-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
HASHES = {
    'spec/11-registries.md': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
    'spec/09-registry.md': '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02',
    'spec/10-resolution.md': '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c',
}
IDS = ('TABLE-03-P', 'TABLE-03-N01', 'TABLE-03-N02',
       'mllm-kem-type-valid', 'mllm-kem-key-length')
SECP_X = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
SECP_Y = bytes.fromhex('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')
P256_X = bytes.fromhex('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296')
P256_Y = bytes.fromhex('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')


def decode(value):
    if (type(value) is not str or not value or
            re.fullmatch('[A-Za-z0-9_-]+', value) is None):
        return None
    try:
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except (ValueError, base64.binascii.Error):
        return None
    return raw if base64.urlsafe_b64encode(raw).decode().rstrip('=') == value else None


def key_type(inp):
    if type(inp) is not dict or set(inp) != {'record', 'document', 'usage'}:
        return None
    record, document = inp['record'], inp['document']
    if (type(record) is not dict or set(record) != {'alg', 'key'} or
            type(document) is not dict or set(document) != {'publicKeyJwk'} or
            type(document['publicKeyJwk']) is not dict):
        return None
    table = {
        'ed25519': ('Ed25519', 'signing', 'OKP', 'Ed25519'),
        'sage-secp256k1-keccak256': ('secp256k1', 'signing', 'EC', 'secp256k1'),
        'ecdsa-p256-sha256': ('P-256', 'signing', 'EC', 'P-256'),
        'x25519': ('X25519', 'key-agreement', 'OKP', 'X25519'),
    }
    row = table.get(record['alg']) if type(record['alg']) is str else None
    if row is None or inp['usage'] != row[1]:
        return None
    raw = decode(record['key'])
    jwk = document['publicKeyJwk']
    members = {'kty', 'crv', 'x', 'y'} if row[2] == 'EC' else {'kty', 'crv', 'x'}
    if raw is None or set(jwk) != members or jwk['kty'] != row[2] or jwk['crv'] != row[3]:
        return None
    x = decode(jwk['x'])
    if x is None or len(x) != 32:
        return None
    if row[2] == 'OKP':
        return row[0] if len(raw) == 32 and raw == x else None
    y = decode(jwk['y'])
    if (y is None or len(y) != 32 or len(raw) != 65 or raw[:1] != b'\x04'
            or raw[1:33] != x or raw[33:] != y):
        return None
    return row[0]


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def check(root=ROOT):
    data = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(data['schema_version'] == 1 and data['spec_revision'] == SPEC and
            data['registries_sha256'] == HASHES['spec/11-registries.md'] and
            data['registry_sha256'] == HASHES['spec/09-registry.md'] and
            data['resolution_sha256'] == HASHES['spec/10-resolution.md'] and
            all(manifest['source_sha256'][path] == digest for path, digest in HASHES.items()) and
            data['scope'] == 'synthetic record-to-JWK encoding; no proof, point validation, fresh registry observation, or DID interoperability claim' and
            tuple(row['id'] for row in data['cases']) == IDS,
            'pinned TABLE-03 sources and bounded cases')
    good, compressed, short, kem, short_kem = [row['input'] for row in data['cases']]
    require(good == {
        'record': {'alg': 'sage-secp256k1-keccak256', 'key': b64(b'\x04' + SECP_X + SECP_Y)},
        'document': {'publicKeyJwk': {'kty': 'EC', 'crv': 'secp256k1',
                                      'x': b64(SECP_X), 'y': b64(SECP_Y)}},
        'usage': 'signing'} and key_type(good) == 'secp256k1',
        'exact uncompressed secp256k1 record/JWK binding')
    require(compressed == dict(good, record={'alg': good['record']['alg'],
                                            'key': b64(b'\x02' + SECP_X)}) and
            short == dict(good, document={'publicKeyJwk': dict(good['document']['publicKeyJwk'],
                                                       x=b64(SECP_X[:-1]))}),
            'isolated compressed-point and short-coordinate defects')
    require(kem == {'record': {'alg': 'x25519', 'key': b64(b'\x09' + b'\x00' * 31)},
                    'document': {'publicKeyJwk': {'kty': 'OKP', 'crv': 'X25519',
                                                  'x': b64(b'\x09' + b'\x00' * 31)}},
                    'usage': 'key-agreement'} and
            short_kem == dict(kem, record={'alg': 'x25519',
                                           'key': b64(b'\x09' + b'\x00' * 30)}) and
            key_type(kem) == 'X25519',
            'isolated exact X25519 role and 31-byte record defect')
    expected_types = ('secp256k1', None, None, 'X25519', None)
    for row, expected_type in zip(data['cases'], expected_types):
        ident = row['id']
        expected = {'verdict': 'ACCEPT' if expected_type else 'REJECT',
                    'output': {'key_type': expected_type} if expected_type else {},
                    'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' / (ident + '.json')).read_bytes())
        require(key_type(row['input']) == expected_type and row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.registry.key.encoding.check',
                                      'input': row['input']}, 'expected': expected},
                'TABLE-03 case contract: ' + ident)
    controls = []
    ed = {'record': {'alg': 'ed25519', 'key': b64(bytes.fromhex('58' + '66' * 31))},
          'document': {'publicKeyJwk': {'kty': 'OKP', 'crv': 'Ed25519',
                                        'x': b64(bytes.fromhex('58' + '66' * 31))}},
          'usage': 'signing'}
    controls.append(('ed25519', ed, 'Ed25519'))
    p256 = {'record': {'alg': 'ecdsa-p256-sha256', 'key': b64(b'\x04' + P256_X + P256_Y)},
            'document': {'publicKeyJwk': {'kty': 'EC', 'crv': 'P-256',
                                          'x': b64(P256_X), 'y': b64(P256_Y)}},
            'usage': 'signing'}
    controls.append(('p256', p256, 'P-256'))
    for name, base, path, value in (
        ('x25519-signing', kem, ('usage',), 'signing'),
        ('x25519-alias', kem, ('record', 'alg'), 'X25519'),
        ('wrong-jwk-curve', good, ('document', 'publicKeyJwk', 'crv'), 'P-256'),
        ('wrong-jwk-kty', good, ('document', 'publicKeyJwk', 'kty'), 'OKP'),
        ('mismatched-coordinate', good, ('document', 'publicKeyJwk', 'y'), b64(SECP_X)),
        ('wrong-prefix', good, ('record', 'key'), b64(b'\x05' + SECP_X + SECP_Y)),
        ('padded-base64url', kem, ('record', 'key'), kem['record']['key'] + '='),
        ('private-jwk-member', kem, ('document', 'publicKeyJwk', 'd'), b64(b'\x01' * 32)),
        ('short-ed25519', ed, ('record', 'key'), b64(b'\x58' + b'\x66' * 30)),
    ):
        changed = copy.deepcopy(base)
        node = changed
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value
        controls.append((name, changed, None))
    require(all(key_type(inp) == expected for _, inp, expected in controls),
            'independent key type, role, length, and encoding controls')
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
