"""Generate bounded exact-key dereference cases from a pinned Registry record."""

import copy
import hashlib
import json
from pathlib import Path

from generate_resolve01_vectors import project


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('RESOLVE-04-P', 'RESOLVE-04-N01', 'RESOLVE-04-N02',
       'RESOLVE-04-N03', 'RESOLVE-04-N04', 'RESOLVE-04-N05')


def body_size(observation):
    body = observation['response']['body']
    observation['response']['body_bytes'] = len(
        json.dumps(body, separators=(',', ':')).encode())


def main():
    raw = (ROOT / 'vectors/0.10.0/reg08-scenarios.json').read_bytes()
    source = json.loads(raw)['cases'][0]['input']
    record = source['response']['body']['record']
    did = record['id']
    good = {'observation': copy.deepcopy(source), 'key_url': did + '#kem-1',
            'required_relationship': 'keyAgreement', 'expected_peer': did}
    method = next(row for row in project(record)['verificationMethod']
                  if row['id'] == good['key_url'])
    missing_fragment = copy.deepcopy(good)
    missing_fragment['key_url'] = did
    unknown = copy.deepcopy(good)
    unknown['key_url'] = did + '#not-registered'
    revoked = copy.deepcopy(good)
    revoked['observation']['response']['body']['record']['keys'][0]['state'] = 'revoked'
    body_size(revoked['observation'])
    service = copy.deepcopy(good)
    service['key_url'] = did + '#api'
    wrong_relationship = copy.deepcopy(good)
    wrong_relationship['required_relationship'] = 'authentication'
    rows = [
        ('RESOLVE-04-P', good, 'ACCEPT', 'exact accepted agreement key'),
        ('RESOLVE-04-N01', missing_fragment, 'REJECT', 'DID URL without key fragment'),
        ('RESOLVE-04-N02', unknown, 'REJECT', 'unknown key fragment'),
        ('RESOLVE-04-N03', revoked, 'REJECT', 'retained revoked agreement key'),
        ('RESOLVE-04-N04', service, 'REJECT', 'service fragment presented as key'),
        ('RESOLVE-04-N05', wrong_relationship, 'REJECT', 'agreement key used for authentication'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': {'verificationMethod': method} if verdict == 'ACCEPT' else {},
                    'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime',
                   'input': {'operation': 'sage.did.key.dereference', 'input': inp},
                   'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c',
             'registry_source_sha256': hashlib.sha256(raw).hexdigest(),
             'scope': 'synthetic current web observation; no live TLS, Registry proof revalidation, or signature trial',
             'cases': cases}
    (ROOT / 'vectors/0.10.0/resolve04-scenarios.json').write_text(
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
