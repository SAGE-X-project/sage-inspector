"""Audit fixed registry records and cryptographic proof isolation."""

import base64
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from current_spec_catalog import ROOT, load, require, sha


IDS = ('REG-01-P', 'REG-01-N01', 'REG-01-N02', 'REG-01-N03',
       'REG-01-N04')
EXTRAS = ('exact-128', 'casefolded-kem-alg', 'unknown-kem-alg')
SOURCE = 'vectors/0.10.0/reg01-scenarios.json'
NOW = 1700000000


def decoded(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_-]+', value)
            is not None, 'canonical base64url characters')
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    require(base64.urlsafe_b64encode(raw).decode().rstrip('=') == value,
            'canonical base64url form')
    return raw


def proof_input(record, key):
    parts = record['id'].split(':')
    require(parts[:3] == ['did', 'sage', 'web'] and len(parts) == 5,
            'fixed public registry DID')
    values = [('web:' + parts[3]).encode(), parts[4].encode(),
              key['name'].encode(), key['alg'].encode(), decoded(key['key'])]
    return b'sage-pop-0.10.0' + b''.join(
        len(value).to_bytes(2, 'big') + value for value in values)


def verify_proofs(record):
    signer = next(key for key in record['keys']
                  if key['name'] == 'signing-1')
    require(signer['alg'] == 'ed25519' and signer['state'] == 'accepted'
            and len(decoded(signer['key'])) == 32,
            'fixed accepted signing key')
    public = Ed25519PublicKey.from_public_bytes(decoded(signer['key']))
    for key in record['keys']:
        require(set(key) in ({'name', 'alg', 'key', 'proof', 'state'},
                             {'name', 'alg', 'key', 'proof', 'state', 'expires'})
                and key['proof']['signer'] == record['id'] + '#signing-1'
                and len(decoded(key['key'])) == 32 and
                len(decoded(key['proof']['value'])) == 64,
                'closed key and proof shape: ' + key['name'])
        public.verify(decoded(key['proof']['value']), proof_input(record, key))


def issues(record):
    """Independent touched-boundary audit, not a receiving core verifier."""
    require(set(record) == {'id', 'controller', 'keys', 'services',
                            'state', 'version'} and
            record['state'] == 'active' and record['version'] == '1' and
            record['controller'] == 'test-controller' and
            1 <= len(record['keys']) <= 129 and
            len(record['services']) <= 16,
            'fixed record envelope')
    key_names = [key['name'] for key in record['keys']]
    service_names = [service['name'] for service in record['services']]
    require(key_names == sorted(key_names) and
            service_names == sorted(service_names) and
            len({key['key'] for key in record['keys']}) == len(record['keys'])
            and all(key['state'] in ('accepted', 'revoked')
                    for key in record['keys']) and
            all(set(service) == {'name', 'type', 'uri'} and
                service['uri'].startswith('https://agents.example.com/')
                for service in record['services']),
            'otherwise valid sorted records and service endpoints')
    verify_proofs(record)
    result = set()
    if len(key_names) != len(set(key_names)):
        result.add('duplicate-key-name')
    if len(service_names) != len(set(service_names)):
        result.add('duplicate-service-name')
    if set(key_names) & set(service_names):
        result.add('fragment-collision')
    if len(record['keys']) > 128:
        result.add('lifetime-key-limit')
    if any(key['alg'] not in ('ed25519', 'x25519')
           for key in record['keys']):
        result.add('kem-alg')
    return result


def check(root=ROOT):
    source_raw = (root / 'vectors/0.10.0/registry-records.json').read_bytes()
    source_rows = {row['id']: row for row in load(source_raw)['cases']}
    suite_raw = (root / SOURCE).read_bytes()
    suite = load(suite_raw)
    require(suite['schema_version'] == 1 and
            suite['spec_revision'] ==
                '5bcf511e604579afa63f434013447f44b6858828' and
            suite['source_sha256'] == sha(source_raw) and
            tuple(row['id'] for row in suite['cases']) == IDS and
            tuple(row['name'] for row in suite['supplemental']) == EXTRAS,
            'REG-01 source and case identity')
    rows = {row['id']: row for row in suite['cases']}
    extras = {row['name']: row for row in suite['supplemental']}
    records = {name: load(bytes.fromhex(row['record_hex']))
               for name, row in {**rows, **extras}.items()}
    source_valid = source_rows['record-valid']['input']['record_hex']
    source_collision = source_rows['record-service-collision']['input']['record_hex']
    require(rows['REG-01-P']['record_hex'] == source_valid and
            rows['REG-01-N03']['record_hex'] == source_collision and
            all(len(bytes.fromhex(row['record_hex'])) <= 65536
                for row in (*rows.values(), *extras.values())),
            'independently audited controls under encoded record limit')
    expected_issues = {
        'REG-01-P': set(),
        'REG-01-N01': {'duplicate-key-name'},
        'REG-01-N02': {'duplicate-service-name'},
        'REG-01-N03': {'fragment-collision'},
        'REG-01-N04': {'lifetime-key-limit'},
        'exact-128': set(),
        'casefolded-kem-alg': {'kem-alg'},
        'unknown-kem-alg': {'kem-alg'},
    }
    for name, record in records.items():
        expected = rows.get(name, extras.get(name))['expected']
        require(issues(record) == expected_issues[name] and
                expected == ('REJECT' if expected_issues[name] else 'ACCEPT'),
                'isolated record defect with valid proof: ' + name)
    control = records['REG-01-P']
    duplicate = records['REG-01-N01']
    require(duplicate['services'] == control['services'] and
            len(duplicate['keys']) == len(control['keys']) + 1 and
            len({key['key'] for key in duplicate['keys']}) ==
                len(duplicate['keys']),
            'duplicate name without duplicated key material')
    duplicate_service = records['REG-01-N02']
    require(duplicate_service['keys'] == control['keys'] and
            len(duplicate_service['services']) == 2 and
            duplicate_service['services'][0]['uri'] !=
                duplicate_service['services'][1]['uri'],
            'duplicate service name with distinct valid endpoints')
    exact = records['exact-128']['keys']
    over = records['REG-01-N04']['keys']
    require(len(exact) == 128 and len(over) == 129 and
            [key for key in over if key['name'] != 'kem-126'] == exact and
            all(key['state'] == 'revoked' for key in over
                if key['name'].startswith('kem-0')),
            'valid 128-entry control and one additional revoked tombstone')
    for name, alg in (('casefolded-kem-alg', 'X25519'),
                      ('unknown-kem-alg', 'curve25519')):
        candidate = records[name]
        require(candidate['keys'][0]['alg'] == alg and
                {**candidate['keys'][0], 'alg': 'x25519',
                 'proof': control['keys'][0]['proof']} == control['keys'][0]
                and candidate['services'] == control['services'],
                'unknown KEM algorithm with re-signed valid proof: ' + name)
    source_input = source_rows['record-valid']['input']
    for ident in IDS:
        row = rows[ident]
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] == 'sage.registry.record.verify'
                and fixture['input']['input'] == {
                    **source_input, 'record_hex': row['record_hex']} and
                fixture['expected'] == {
                    'verdict': row['expected'],
                    'output': {'valid': True} if ident == IDS[0] else {},
                    'effects': {}},
                'REG-01 runtime fixture contract: ' + ident)
    spec = (root / 'verification/0.10.0/snapshot/spec/09-registry.md').read_text()
    current = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require('1–128 entries including tombstones' in spec and
            'Service names MUST NOT collide with any key name' in spec and
            'Names and key bytes' in spec and
            current['spec_revision'] ==
                '5bcf511e604579afa63f434013447f44b6858828' and
            current['source_sha256']['spec/09-registry.md'] ==
                '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02' and
            current['source_sha256']['spec/11-registries.md'] ==
                'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
            'historical common rules and pinned current KEM algorithm sources')
    return len(IDS), len(EXTRAS)


if __name__ == '__main__':
    print('Verified REG-01 cases and controls:', check())
