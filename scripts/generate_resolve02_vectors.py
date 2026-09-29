"""Generate bounded resolution cases from the pinned web Registry fixture."""

import copy
import hashlib
import json
from pathlib import Path

from generate_resolve01_vectors import project


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('RESOLVE-02-P', 'RESOLVE-02-N01', 'RESOLVE-02-N02',
       'RESOLVE-02-N03', 'RESOLVE-02-N04', 'RESOLVE-02-N05')


def body_size(inp):
    body = inp['response']['body']
    inp['response']['body_bytes'] = len(json.dumps(body, separators=(',', ':')).encode())


def main():
    registry_raw = (ROOT / 'vectors/0.10.0/reg08-scenarios.json').read_bytes()
    source = json.loads(registry_raw)['cases'][0]['input']
    good = copy.deepcopy(source)
    good['local_version_floor'] = 1
    record = good['response']['body']['record']
    did = record['id']
    output = {
        'didDocument': project(record),
        'didDocumentMetadata': {
            'deactivated': False, 'versionId': record['version'],
            'sage': {'state': 'active', 'controller': record['controller'],
                     'observedAt': good['response']['body']['issued'],
                     'source': good['policy']['configured_origin'],
                     'observedTime': good['trusted_now']}},
        'didResolutionMetadata': {'contentType': 'application/did+json'}}
    unknown = copy.deepcopy(good)
    unknown['response']['status'] = 404
    unknown['response']['body']['record'] = None
    body_size(unknown)
    malformed = copy.deepcopy(good)
    malformed_record = malformed['response']['body']['record']
    malformed_record['state'] = 'deactivated'
    del malformed_record['keys'][0]['proof']
    body_size(malformed)
    stale = copy.deepcopy(good)
    stale['trusted_now'] = good['response']['body']['expires']
    unauthenticated = copy.deepcopy(good)
    unauthenticated['request']['authenticated_tls_origin'] = None
    cached = copy.deepcopy(good)
    cached['response']['source'] = 'intermediary-positive-cache'
    rows = [
        ('RESOLVE-02-P', good, 'ACCEPT', 'one current configured web observation'),
        ('RESOLVE-02-N01', unknown, 'REJECT', 'identifier absent at authority'),
        ('RESOLVE-02-N02', malformed, 'REJECT', 'inactive record with missing key proof'),
        ('RESOLVE-02-N03', stale, 'REJECT', 'observation expires at trusted clock'),
        ('RESOLVE-02-N04', unauthenticated, 'REJECT', 'TLS origin not authenticated'),
        ('RESOLVE-02-N05', cached, 'REJECT', 'intermediated positive cache reused'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': output if verdict == 'ACCEPT' else {},
                    'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime',
                   'input': {'operation': 'sage.did.resolve', 'input': inp},
                   'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c',
             'registry_source_sha256': hashlib.sha256(registry_raw).hexdigest(),
             'scope': 'synthetic configured web observation; no live TLS, operator provenance, signature revalidation, or blockchain finality',
             'cases': cases}
    (ROOT / 'vectors/0.10.0/resolve02-scenarios.json').write_text(
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
    print('Generated six RESOLVE-02 partial runtime fixtures')


if __name__ == '__main__':
    main()
