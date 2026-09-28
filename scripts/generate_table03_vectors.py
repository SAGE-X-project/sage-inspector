"""Generate bounded registry-key and DID JWK encoding fixtures."""

import base64
import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
SECP_X = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
SECP_Y = bytes.fromhex('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')
KEM_PUBLIC = bytes.fromhex('09' + '00' * 31)


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def main():
    valid = {'record': {'alg': 'sage-secp256k1-keccak256',
                        'key': b64(b'\x04' + SECP_X + SECP_Y)},
             'document': {'publicKeyJwk': {'kty': 'EC', 'crv': 'secp256k1',
                                           'x': b64(SECP_X), 'y': b64(SECP_Y)}},
             'usage': 'signing'}
    compressed = copy.deepcopy(valid)
    compressed['record']['key'] = b64(b'\x02' + SECP_X)
    short_coordinate = copy.deepcopy(valid)
    short_coordinate['document']['publicKeyJwk']['x'] = b64(SECP_X[:-1])
    kem = {'record': {'alg': 'x25519', 'key': b64(KEM_PUBLIC)},
           'document': {'publicKeyJwk': {'kty': 'OKP', 'crv': 'X25519',
                                        'x': b64(KEM_PUBLIC)}},
           'usage': 'key-agreement'}
    short_kem = copy.deepcopy(kem)
    short_kem['record']['key'] = b64(KEM_PUBLIC[:-1])
    rows = [
        ('TABLE-03-P', valid, 'ACCEPT', 'matching uncompressed secp256k1 record and JWK'),
        ('TABLE-03-N01', compressed, 'REJECT', 'compressed secp256k1 record encoding'),
        ('TABLE-03-N02', short_coordinate, 'REJECT', 'short JWK coordinate'),
        ('mllm-kem-type-valid', kem, 'ACCEPT', 'exact x25519 KEM role and 32-byte key'),
        ('mllm-kem-key-length', short_kem, 'REJECT', '31-byte x25519 record key'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': {'key_type': 'secp256k1' if ident == 'TABLE-03-P'
                               else 'X25519'} if verdict == 'ACCEPT' else {},
                    'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'runtime',
                   'input': {'operation': 'sage.registry.key.encoding.check',
                             'input': inp}, 'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'registries_sha256': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
             'registry_sha256': '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02',
             'resolution_sha256': '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c',
             'scope': 'synthetic record-to-JWK encoding; no proof, point validation, fresh registry observation, or DID interoperability claim',
             'cases': cases}
    (ROOT / 'vectors/0.10.0/table03-scenarios.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    ids = {row[0] for row in rows}
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in ids]
    for ident in sorted(ids):
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
