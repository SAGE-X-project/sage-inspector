"""Generate bounded DID document projection fixtures from a pinned record."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('RESOLVE-01-P', 'RESOLVE-01-N01', 'RESOLVE-01-N02', 'RESOLVE-01-N03')


def project(record):
    did = record['id']
    document = {'id': did, 'verificationMethod': [], 'authentication': [],
                'assertionMethod': [], 'keyAgreement': [], 'service': []}
    if record['state'] not in ('created', 'deactivated'):
        for key in sorted(record['keys'], key=lambda item: item['name'].encode('ascii')):
            if key['state'] != 'accepted':
                continue
            ident = did + '#' + key['name']
            curve = {'ed25519': 'Ed25519', 'x25519': 'X25519'}[key['alg']]
            document['verificationMethod'].append({
                'id': ident, 'type': 'JsonWebKey2020', 'controller': did,
                'publicKeyJwk': {'kty': 'OKP', 'crv': curve, 'x': key['key']}})
            if key['alg'] == 'x25519':
                document['keyAgreement'].append(ident)
            else:
                document['authentication'].append(ident)
                document['assertionMethod'].append(ident)
    for service in sorted(record['services'], key=lambda item: item['name'].encode('ascii')):
        document['service'].append({'id': did + '#' + service['name'],
                                    'type': service['type'],
                                    'serviceEndpoint': service['uri']})
    return document


def main():
    record_raw = (ROOT / 'vectors/0.10.0/registry-records.json').read_bytes()
    original = next(row['input']['record'] for row in json.loads(record_raw)['cases']
                    if row['id'] == 'resolve-created')
    record = copy.deepcopy(original)
    record['state'] = 'active'
    good = project(record)
    fabricated = copy.deepcopy(good)
    fabricated['authentication'][0] = record['id'] + '#fabricated'
    missing_id = copy.deepcopy(good)
    del missing_id['id']
    wrong_x = copy.deepcopy(good)
    signing = next(method for method in wrong_x['verificationMethod']
                   if method['id'].endswith('#signing-1'))
    value = signing['publicKeyJwk']['x']
    signing['publicKeyJwk']['x'] = ('B' if value[0] != 'B' else 'C') + value[1:]
    rows = [
        ('RESOLVE-01-P', good, 'ACCEPT', 'exact active record projection'),
        ('RESOLVE-01-N01', fabricated, 'REJECT', 'fabricated authentication reference'),
        ('RESOLVE-01-N02', missing_id, 'REJECT', 'missing document identifier'),
        ('RESOLVE-01-N03', wrong_x, 'REJECT', 'public key coordinate differs from registry'),
    ]
    cases = []
    for ident, candidate, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': {'didDocument': good} if verdict == 'ACCEPT' else {},
                    'effects': {}}
        inp = {'record': record, 'candidate': candidate,
               'media_type': 'application/did+json'}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime',
                   'input': {'operation': 'sage.did.document.verify', 'input': inp},
                   'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c',
             'record_source_sha256': hashlib.sha256(record_raw).hexdigest(),
             'scope': 'synthetic post-validation projection; record proofs, freshness, and independent DID consumer are outside this vector',
             'cases': cases}
    (ROOT / 'vectors/0.10.0/resolve01-scenarios.json').write_text(
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
