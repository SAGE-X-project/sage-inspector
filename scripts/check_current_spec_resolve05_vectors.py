"""Independently audit bounded HTTP resolution and problem-detail fixtures."""

import copy
import json
from urllib.parse import unquote, urlsplit

from check_current_spec_resolve02_vectors import decision as resolution_decision
from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/resolve05-scenarios.json'
RESOLUTION_SOURCE = 'vectors/0.10.0/resolve02-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CHAPTER_SHA = '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c'
IDS = ('RESOLVE-05-P', 'RESOLVE-05-N01', 'RESOLVE-05-N02',
       'RESOLVE-05-N03', 'RESOLVE-05-N04')
PROBLEM_BASE = 'https://sage-x-project.github.io/sage-spec/errors/'
PROBLEMS = (
    ('id.malformed', 'Malformed identifier', 400),
    ('id.unknown-kind', 'Unsupported registry kind', 400),
    ('version.unsupported', 'Unsupported protocol version', 400),
    ('record.not-found', 'Record not found', 404),
    ('key.not-in-record', 'Key not found', 404),
    ('record.unreachable', 'Registry unavailable', 502),
    ('record.stale', 'Registry observation stale', 502),
    ('record.invalid', 'Registry record invalid', 502),
    ('size.exceeded', 'Input too large', 413),
)


def decision(inp, expected_body):
    observation = inp['observation']
    if resolution_decision(observation) != 'ACCEPT':
        return 'REJECT'
    request, response = inp['request'], inp['response']
    origin = observation['policy']['configured_origin']
    parsed = urlsplit(request['url'])
    prefix = '/0.10.0/identifiers/'
    encoded = parsed.path[len(prefix):] if parsed.path.startswith(prefix) else ''
    if (request['method'] != 'GET' or
            parsed.scheme != 'https' or parsed.netloc != origin.removeprefix('https://') or
            parsed.query or parsed.fragment or not encoded or '/' in encoded or
            unquote(encoded) != observation['did'] or
            request['authenticated_tls_origin'] != origin or
            request['headers'].get('X-SAGE-Version') != '0.10.0' or
            response['headers'].get('X-SAGE-Version') != '0.10.0' or
            response['headers'].get('Cache-Control') != 'no-store' or
            response['status'] != 200 or response['location'] is not None or
            response['source'] != 'direct-origin'):
        return 'REJECT'
    accept = request['headers'].get('Accept')
    media = response['headers'].get('Content-Type')
    if accept not in ('application/json', 'application/did+json') or accept != media:
        return 'REJECT'
    body = expected_body if media == 'application/json' else expected_body['didDocument']
    if (response['body'] != body or
            media == 'application/did+json' and inp['consumer_purpose'] == 'authentication'):
        return 'REJECT'
    compact = len(json.dumps(body, separators=(',', ':')).encode())
    padding = response['trailing_whitespace_bytes']
    if (type(padding) is not int or padding < 0 or
            response['body_bytes'] != compact + padding or
            response['body_bytes'] > 262144):
        return 'REJECT'
    return 'ACCEPT'


def problem_decision(problem):
    mapping = {code: (title, status) for code, title, status in PROBLEMS}
    code = problem['code']
    if code not in mapping:
        return 'REJECT'
    title, status = mapping[code]
    if (problem['http_status'] != status or
            problem['headers'] != {'X-SAGE-Version': '0.10.0',
                                   'Cache-Control': 'no-store',
                                   'Content-Type': 'application/problem+json'} or
            problem['body'] != {'type': PROBLEM_BASE + code,
                                'title': title, 'status': status}):
        return 'REJECT'
    return 'ACCEPT'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    raw = (root / RESOLUTION_SOURCE).read_bytes()
    source = load(raw)['cases'][0]
    body = source['expected']['output']
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == CHAPTER_SHA and
            manifest['source_sha256']['spec/10-resolution.md'] == CHAPTER_SHA and
            suite['resolution_source_sha256'] == sha(raw) and
            suite['scope'] == 'synthetic HTTP exchange; no live TLS, problem-type publication, independent RFC 9457 consumer, or authenticated Registry fetch' and
            tuple(row['id'] for row in suite['cases']) == IDS and
            suite['problem_type_publication'] == 'NOT_VERIFIED',
            'pinned RESOLVE-05 sources, scope, and publication gap')
    good = suite['cases'][0]['input']
    require(good['observation'] == source['input'] and
            good['response']['body'] == body and
            good['response']['trailing_whitespace_bytes'] == 0 and
            decision(good, body) == 'ACCEPT',
            'versioned direct-origin resolution envelope')
    for index, row in enumerate(suite['cases']):
        ident = row['id']
        verdict = 'ACCEPT' if index == 0 else 'REJECT'
        expected = {'verdict': verdict,
                    'output': body if index == 0 else {}, 'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(decision(row['input'], body) == verdict and
                row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.did.http.resolve',
                                      'input': row['input']},
                            'expected': expected},
                'RESOLVE-05 case contract: ' + ident)
    wrong_media, redirect, oversized, cached = [row['input']
                                                 for row in suite['cases'][1:]]
    require(wrong_media['response']['headers']['Content-Type'] == 'application/did-resolution' and
            redirect['response']['status'] == 302 and
            redirect['response']['location'] == 'https://other.example/resolve' and
            oversized['response']['body_bytes'] == 262145 and
            oversized['response']['trailing_whitespace_bytes'] > 0 and
            cached['response']['source'] == 'positive-cache',
            'isolated media, redirect, byte-limit, and cache defects')
    problems = suite['problem_cases']
    require(tuple(row['code'] for row in problems) == tuple(row[0] for row in PROBLEMS) and
            all(problem_decision(row) == 'ACCEPT' for row in problems),
            'nine exact public problem-detail mappings')
    sample = problems[0]
    for name, mutate in (
        ('type', lambda x: x['body'].update(type='https://other.example/errors/id.malformed')),
        ('title', lambda x: x['body'].update(title='Wrong title')),
        ('problem-status', lambda x: x['body'].update(status=404)),
        ('http-status', lambda x: x.update(http_status=404)),
        ('partial-document', lambda x: x['body'].update(didDocument={})),
        ('wrong-media', lambda x: x['headers'].update({'Content-Type': 'application/json'})),
    ):
        changed = copy.deepcopy(sample)
        mutate(changed)
        require(problem_decision(changed) == 'REJECT', 'problem control: ' + name)
    for name, mutate in (
        ('request-version', lambda x: x['request']['headers'].update({'X-SAGE-Version': '0.9.0'})),
        ('query', lambda x: x['request'].update(url=x['request']['url'] + '?current=1')),
        ('extra-segment', lambda x: x['request'].update(url=x['request']['url'] + '/extra')),
        ('double-encoding', lambda x: x['request'].update(url=x['request']['url'].replace('%3A', '%253A'))),
        ('response-version', lambda x: x['response']['headers'].update({'X-SAGE-Version': '0.9.0'})),
        ('missing-no-store', lambda x: x['response']['headers'].update({'Cache-Control': 'max-age=60'})),
    ):
        changed = copy.deepcopy(good)
        mutate(changed)
        require(decision(changed, body) == 'REJECT', 'HTTP control: ' + name)
    document_only = copy.deepcopy(good)
    document_only['request']['headers']['Accept'] = 'application/did+json'
    document_only['response']['headers']['Content-Type'] = 'application/did+json'
    document_only['response']['body'] = body['didDocument']
    document_only['response']['body_bytes'] = len(json.dumps(
        body['didDocument'], separators=(',', ':')).encode())
    require(decision(document_only, body) == 'ACCEPT', 'document-only inspection form')
    document_only['consumer_purpose'] = 'authentication'
    require(decision(document_only, body) == 'REJECT',
            'bare document cannot authorize authentication')
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(all(any(binding['id'] == ident and binding['coverage'] == 'partial' and
                    binding['fixture_sha256'] == sha((root / 'vectors/0.10.0/current-spec' /
                                                     (ident + '.json')).read_bytes())
                    for binding in bindings['bindings']) for ident in IDS),
            'partial runtime case bindings')
    return len(IDS), len(problems), 14


if __name__ == '__main__':
    print(check())
