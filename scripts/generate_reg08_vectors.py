"""Prepare web authority fixtures and record the media-type decision gap."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
DID = 'did:sage:web:agents.example.com:alice'
ORIGIN = 'https://agents.example.com'
URL = ORIGIN + '/.well-known/sage/agents/alice'
IDS = ('REG-08-P', 'REG-08-N01', 'REG-08-N02', 'REG-08-N03')


def base(record):
    body = {'record': record, 'issued': 100, 'expires': 105}
    return {
        'did': DID, 'protocol_version': '0.10.0',
        'policy': {'allow_web': True, 'require_blockchain': False,
                   'configured_origin': ORIGIN,
                   'approved_origins': [ORIGIN],
                   'approved_destinations': ['agents.example.com']},
        'request': {'url': URL, 'method': 'GET',
                    'cache_control': 'no-cache, no-store',
                    'follow_redirects': False,
                    'authenticated_tls_origin': ORIGIN},
        'response': {'status': 200, 'redirect_location': None,
                     'source': 'direct-origin', 'cache_control': 'no-store',
                     'body': body,
                     'body_bytes': len(json.dumps(body, separators=(',', ':')).encode())},
        'trusted_now': 102,
    }


def main():
    registry_raw = (ROOT / 'vectors/0.10.0/registry-records.json').read_bytes()
    records = json.loads(registry_raw)['cases']
    source = next(row['input']['record'] for row in records
                  if row['id'] == 'resolve-created')
    record = copy.deepcopy(source)
    record['state'] = 'active'
    good = base(record)
    redirect = copy.deepcopy(good)
    redirect['response']['status'] = 302
    redirect['response']['redirect_location'] = 'https://other.example/record'
    stale = copy.deepcopy(good)
    stale['response']['source'] = 'intermediary-positive-cache'
    missing = copy.deepcopy(good)
    missing['policy']['configured_origin'] = None
    rows = [
        ('REG-08-P', good, 'ACCEPT',
         'fresh exact-origin one-operation read'),
        ('REG-08-N01', redirect, 'REJECT',
         'redirect to another origin'),
        ('REG-08-N02', stale, 'REJECT',
         'intermediated positive-cache response'),
        ('REG-08-N03', missing, 'REJECT',
         'missing configured authority'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': {'verdict': verdict,
                                   'output': {'record_id': DID} if verdict == 'ACCEPT' else {},
                                   'effects': {}}})
    controls = []
    for name, mutate in (
        ('cached-304', lambda x: x['response'].update(status=304)),
        ('missing-no-store', lambda x: x['response'].update(cache_control='max-age=60')),
        ('expired', lambda x: x.update(trusted_now=105)),
        ('oversize', lambda x: x['response'].update(body_bytes=69633)),
        ('blockchain-required', lambda x: x['policy'].update(require_blockchain=True)),
        ('unapproved-destination', lambda x: x['policy'].update(approved_destinations=[])),
    ):
        inp = copy.deepcopy(good)
        mutate(inp)
        controls.append({'id': name, 'input': inp, 'expected_verdict': 'REJECT'})
    suite = {
        'schema_version': 1, 'spec_revision': SPEC,
        'source_sha256': '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02',
        'record_source_sha256': hashlib.sha256(registry_raw).hexdigest(),
        'scope': 'synthetic HTTP response and trusted clock; no network, TLS, operator writes, or tombstones',
        'cases': cases, 'supplemental': controls,
        'unresolved_case': {
            'id': 'REG-08-N04', 'condition': 'Content-Type: text/plain',
            'decision': 'UNSPECIFIED',
            'reason': 'Chapter 09 does not define an accepted media type for the web origin record response; chapter 10 media types govern the separate public resolution API.'},
    }
    (ROOT / 'vectors/0.10.0/reg08-scenarios.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    for row in cases:
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': row['id'], 'track': 'runtime',
                   'input': {'operation': 'sage.registry.web.resolve',
                             'input': row['input']},
                   'expected': row['expected']}
        (ROOT / 'vectors/0.10.0/current-spec' /
         (row['id'] + '.json')).write_text(json.dumps(fixture, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    for ident in IDS:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')
    print('Generated four REG-08 cases, six controls, and one explicit spec gap')


if __name__ == '__main__':
    main()
