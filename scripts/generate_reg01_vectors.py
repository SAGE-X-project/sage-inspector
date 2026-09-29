"""Generate isolated record-shape and lifetime-key boundary fixtures."""

import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

from generate_registry_vectors import (DID, KEM, KEY, RECORD, RID, SK,
                                       b64, challenge, entry, jcs, public)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'vectors/0.10.0/registry-records.json'
OUTPUT = ROOT / 'vectors/0.10.0/reg01-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'


def kem(name, index):
    seed = hashlib.sha256(('public REG-01 KEM ' + str(index)).encode()).digest()
    key = entry(name, 'x25519', public(
        x25519.X25519PrivateKey.from_private_bytes(seed)), 'signing-1')
    key['state'] = 'revoked'
    return key


def with_key(record, key):
    result = copy.deepcopy(record)
    result['keys'].append(key)
    result['keys'].sort(key=lambda value: value['name'])
    return result


def alg_variant(value):
    result = copy.deepcopy(RECORD)
    key = result['keys'][0]
    key['alg'] = value
    decoded = base64.urlsafe_b64decode(key['key'] + '==')
    key['proof']['value'] = b64(SK.sign(challenge(
        RID, 'alice', key['name'], value, decoded)))
    return result


def main():
    source = SOURCE.read_bytes()
    source_rows = {row['id']: row for row in json.loads(source)['cases']}
    valid = json.loads(bytes.fromhex(source_rows['record-valid']['input']
                                      ['record_hex']))
    collision = json.loads(bytes.fromhex(source_rows['record-service-collision']
                                          ['input']['record_hex']))
    assert valid == RECORD and valid['id'] == DID and valid['keys'] == [KEM, KEY]
    duplicate_name = with_key(RECORD, kem('kem-1', 1000))
    duplicate_service = copy.deepcopy(RECORD)
    duplicate_service['services'].append({
        'name': 'api', 'type': 'Agent',
        'uri': 'https://agents.example.com/other'})
    exact_128 = copy.deepcopy(RECORD)
    for index in range(126):
        exact_128 = with_key(exact_128, kem('kem-' + format(index, '03d'), index))
    over_128 = with_key(exact_128, kem('kem-126', 126))
    cases = [
        ('REG-01-P', valid, 'ACCEPT', 'closed valid record'),
        ('REG-01-N01', duplicate_name, 'REJECT', 'duplicate key name only'),
        ('REG-01-N02', duplicate_service, 'REJECT', 'duplicate service name only'),
        ('REG-01-N03', collision, 'REJECT', 'key and service name collision'),
        ('REG-01-N04', over_128, 'REJECT', '129 lifetime key entries'),
    ]
    extras = [
        ('exact-128', exact_128, 'ACCEPT', '128 lifetime key entries'),
        ('casefolded-kem-alg', alg_variant('X25519'), 'REJECT',
         'valid proof but disallowed KEM algorithm case'),
        ('unknown-kem-alg', alg_variant('curve25519'), 'REJECT',
         'valid proof but unknown KEM algorithm alias'),
    ]
    suite = {
        'schema_version': 1, 'spec_revision': SPEC,
        'source_sha256': hashlib.sha256(source).hexdigest(),
        'scope': 'fixed public records and proofs; no registry write, lookup, or network request',
        'cases': [{'id': ident, 'record_hex': jcs(record).hex(),
                   'expected': expected, 'purpose': purpose}
                  for ident, record, expected, purpose in cases],
        'supplemental': [{'name': name, 'record_hex': jcs(record).hex(),
                          'expected': expected, 'purpose': purpose}
                         for name, record, expected, purpose in extras],
    }
    OUTPUT.write_text(json.dumps(suite, indent=2) + '\n')
    print('Generated', len(cases), 'REG-01 cases and', len(extras),
          'controls; largest record', max(len(jcs(record)) for _, record, _, _
                                         in cases + extras), 'bytes')


if __name__ == '__main__':
    main()
