"""Audit bounded web authority cases while preserving the media-type gap."""

import ipaddress
import json
import re

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/reg08-scenarios.json'
RECORD_SOURCE = 'vectors/0.10.0/registry-records.json'
IDS = ('REG-08-P', 'REG-08-N01', 'REG-08-N02', 'REG-08-N03')
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CHAPTER_SHA = '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02'


def decision(inp):
    policy, request, response = inp['policy'], inp['request'], inp['response']
    origin = policy['configured_origin']
    if policy['require_blockchain'] or not policy['allow_web'] or not origin:
        return 'REJECT'
    domain = inp['did'].split(':')[3]
    try:
        ipaddress.ip_address(domain)
        return 'REJECT'
    except ValueError:
        pass
    labels = domain.split('.')
    if (len(domain.encode()) > 64 or
            not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                    for label in labels)
            or origin != 'https://' + domain or
            origin not in policy['approved_origins'] or
            domain not in policy['approved_destinations']):
        return 'REJECT'
    expected_url = origin + '/.well-known/sage/agents/' + inp['did'].split(':')[-1]
    if (request['url'] != expected_url or request['method'] != 'GET'
            or request['authenticated_tls_origin'] != origin
            or request['follow_redirects'] is not False
            or request['cache_control'] != 'no-cache, no-store'):
        return 'REJECT'
    if (response['status'] != 200 or response['redirect_location'] is not None
            or response['source'] != 'direct-origin'
            or response['cache_control'] != 'no-store'
            or response['body_bytes'] > 69632
            or response['body_bytes'] != len(json.dumps(
                response['body'], separators=(',', ':')).encode())):
        return 'REJECT'
    body = response['body']
    if (set(body) != {'record', 'issued', 'expires'}
            or type(body['issued']) is not int or type(body['expires']) is not int
            or not (body['issued'] <= inp['trusted_now'] < body['expires'])
            or not (0 < body['expires'] - body['issued'] <= 5)
            or body['record']['id'] != inp['did']):
        return 'REJECT'
    return 'ACCEPT'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    source_raw = (root / RECORD_SOURCE).read_bytes()
    source = load(source_raw)
    original = next(row['input']['record'] for row in source['cases']
                    if row['id'] == 'resolve-created')
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC
            and suite['source_sha256'] == CHAPTER_SHA
            and manifest['source_sha256']['spec/09-registry.md'] == CHAPTER_SHA
            and suite['record_source_sha256'] == sha(source_raw)
            and tuple(row['id'] for row in suite['cases']) == IDS
            and suite['scope'] ==
                'synthetic HTTP response and trusted clock; no network, TLS, operator writes, or tombstones',
            'pinned REG-08 sources and bounded case inventory')
    positive = suite['cases'][0]['input']
    expected_record = dict(original, state='active')
    require(positive['did'] == 'did:sage:web:agents.example.com:alice'
            and positive['response']['body']['record'] == expected_record
            and positive['response']['body']['issued'] == 100
            and positive['response']['body']['expires'] == 105
            and positive['trusted_now'] == 102
            and decision(positive) == 'ACCEPT',
            'one-operation current web authority control')
    redirect, stale, missing = [row['input'] for row in suite['cases'][1:]]
    require(redirect['policy'] == positive['policy'] and
            redirect['request'] == positive['request'] and
            redirect['response']['status'] == 302 and
            redirect['response']['redirect_location'] ==
                'https://other.example/record' and
            stale['response']['source'] == 'intermediary-positive-cache' and
            stale['response']['status'] == 200 and
            missing['policy']['configured_origin'] is None and
            missing['response'] == positive['response'],
            'isolated redirect, stale cache, and missing authority defects')
    for row in suite['cases']:
        ident = row['id']
        verdict = 'ACCEPT' if ident == 'REG-08-P' else 'REJECT'
        expected = {'verdict': verdict,
                    'output': {'record_id': positive['did']} if verdict == 'ACCEPT' else {},
                    'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(decision(row['input']) == verdict and row['expected'] == expected
                and fixture == {'schema_version': 1,
                                'spec_revision': SPEC, 'id': ident,
                                'track': 'runtime',
                                'input': {'operation':
                                          'sage.registry.web.resolve',
                                          'input': row['input']},
                                'expected': expected},
                'REG-08 bounded case contract: ' + ident)
    controls = suite['supplemental']
    require(tuple(row['id'] for row in controls) ==
            ('cached-304', 'missing-no-store', 'expired', 'oversize',
             'blockchain-required', 'unapproved-destination')
            and all(row['expected_verdict'] == decision(row['input']) == 'REJECT'
                    for row in controls),
            'independent web trust and freshness controls')
    unresolved = suite['unresolved_case']
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(unresolved['id'] == 'REG-08-N04'
            and unresolved['condition'] == 'Content-Type: text/plain'
            and unresolved['decision'] == 'UNSPECIFIED'
            and any(row['id'] == 'REG-08-N04' and row['track'] == 'runtime'
                    and row['coverage'] == 'partial'
                    for row in bindings['bindings'])
            and not (root / 'vectors/0.10.0/current-spec/REG-08-N04.json').exists(),
            'no invented media-type verdict')
    return len(IDS), len(controls), unresolved['id']


if __name__ == '__main__':
    print(check())
