"""Independently audit bounded DID document projection cases."""

import base64
import copy
import json

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/resolve01-scenarios.json'
RECORD_SOURCE = 'vectors/0.10.0/registry-records.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CHAPTER_SHA = '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c'
IDS = ('RESOLVE-01-P', 'RESOLVE-01-N01', 'RESOLVE-01-N02', 'RESOLVE-01-N03')
DOCUMENT_MEMBERS = {'id', 'verificationMethod', 'authentication',
                    'assertionMethod', 'keyAgreement', 'service'}


def canonical_key(value):
    try:
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
        return (len(raw) == 32 and
                base64.urlsafe_b64encode(raw).rstrip(b'=').decode() == value)
    except (ValueError, TypeError):
        return False


def decision(record, document, media_type='application/did+json'):
    if media_type != 'application/did+json' or not isinstance(document, dict):
        return 'REJECT'
    if set(document) != DOCUMENT_MEMBERS or document['id'] != record['id']:
        return 'REJECT'
    did = record['id']
    if any(not isinstance(document[name], list) for name in DOCUMENT_MEMBERS - {'id'}):
        return 'REJECT'
    if len({item['name'] for item in record['keys'] + record['services']}) != len(record['keys']) + len(record['services']):
        return 'REJECT'
    active = [] if record['state'] in ('created', 'deactivated') else [
        key for key in record['keys'] if key['state'] == 'accepted' and
        (key.get('expires') is None or key['expires'] > record.get('trusted_now', 0))]
    active.sort(key=lambda item: item['name'].encode('ascii'))
    methods = document['verificationMethod']
    if len(methods) != len(active):
        return 'REJECT'
    auth, agreement = [], []
    for method, key in zip(methods, active):
        ident = did + '#' + key['name']
        curve = {'ed25519': 'Ed25519', 'x25519': 'X25519'}.get(key['alg'])
        jwk = method.get('publicKeyJwk') if isinstance(method, dict) else None
        if (set(method) != {'id', 'type', 'controller', 'publicKeyJwk'} or
                method['id'] != ident or method['type'] != 'JsonWebKey2020' or
                method['controller'] != did or not isinstance(jwk, dict) or
                set(jwk) != {'kty', 'crv', 'x'} or jwk['kty'] != 'OKP' or
                jwk['crv'] != curve or not canonical_key(jwk['x']) or
                jwk['x'] != key['key']):
            return 'REJECT'
        (agreement if key['alg'] == 'x25519' else auth).append(ident)
    if (document['authentication'] != auth or
            document['assertionMethod'] != auth or
            document['keyAgreement'] != agreement):
        return 'REJECT'
    services = sorted(record['services'], key=lambda item: item['name'].encode('ascii'))
    expected_services = [{'id': did + '#' + row['name'], 'type': row['type'],
                          'serviceEndpoint': row['uri']} for row in services]
    return 'ACCEPT' if document['service'] == expected_services else 'REJECT'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    raw = (root / RECORD_SOURCE).read_bytes()
    original = next(row['input']['record'] for row in load(raw)['cases']
                    if row['id'] == 'resolve-created')
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == CHAPTER_SHA and
            manifest['source_sha256']['spec/10-resolution.md'] == CHAPTER_SHA and
            suite['record_source_sha256'] == sha(raw) and
            tuple(row['id'] for row in suite['cases']) == IDS and
            suite['scope'] == 'synthetic post-validation projection; record proofs, freshness, and independent DID consumer are outside this vector',
            'pinned RESOLVE-01 sources and scope')
    positive = suite['cases'][0]
    record, document = positive['input']['record'], positive['input']['candidate']
    require(record == dict(original, state='active') and
            decision(record, document) == 'ACCEPT' and
            len(document['verificationMethod']) == 2 and
            len(document['service']) == 1,
            'active record and exact projection')
    for index, row in enumerate(suite['cases']):
        ident = row['id']
        expected_verdict = 'ACCEPT' if index == 0 else 'REJECT'
        inp = row['input']
        expected = {'verdict': expected_verdict,
                    'output': {'didDocument': document} if index == 0 else {},
                    'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(inp['record'] == record and
                inp['media_type'] == 'application/did+json' and
                decision(record, inp['candidate']) == expected_verdict and
                row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.did.document.verify',
                                      'input': inp}, 'expected': expected},
                'RESOLVE-01 case contract: ' + ident)
    fabricated, missing, mismatch = [row['input']['candidate']
                                     for row in suite['cases'][1:]]
    require(fabricated == dict(document, authentication=[record['id'] + '#fabricated']) and
            missing == {key: value for key, value in document.items() if key != 'id'} and
            len(mismatch['verificationMethod']) == len(document['verificationMethod']) and
            mismatch['verificationMethod'][0] == document['verificationMethod'][0] and
            mismatch['verificationMethod'][1]['publicKeyJwk']['x'] !=
                document['verificationMethod'][1]['publicKeyJwk']['x'] and
            canonical_key(mismatch['verificationMethod'][1]['publicKeyJwk']['x']),
            'isolated reference, ID, and canonical coordinate defects')
    for mutate in ('type', 'context', 'private', 'curve'):
        changed = copy.deepcopy(document)
        method = changed['verificationMethod'][1]
        if mutate == 'type':
            method['type'] = 'JsonWebKey'
        elif mutate == 'context':
            changed['@context'] = 'https://www.w3.org/ns/did/v1'
        elif mutate == 'private':
            method['publicKeyJwk']['d'] = method['publicKeyJwk']['x']
        else:
            method['publicKeyJwk']['crv'] = 'P-256'
        require(decision(record, changed) == 'REJECT', 'projection control: ' + mutate)
    for state in ('created', 'deactivated'):
        changed = dict(record, state=state)
        empty = copy.deepcopy(document)
        for member in ('verificationMethod', 'authentication', 'assertionMethod', 'keyAgreement'):
            empty[member] = []
        require(decision(changed, empty) == 'ACCEPT' and
                decision(changed, document) == 'REJECT', 'inactive document: ' + state)
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(all(any(binding['id'] == ident and binding['coverage'] == 'partial' and
                    binding['fixture_sha256'] == sha((root / 'vectors/0.10.0/current-spec' /
                                                     (ident + '.json')).read_bytes())
                    for binding in bindings['bindings']) for ident in IDS),
            'partial case bindings')
    return len(IDS), 6


if __name__ == '__main__':
    print(check())
