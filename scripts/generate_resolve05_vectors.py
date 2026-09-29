"""Generate bounded HTTP resolution binding and problem-detail fixtures."""

import copy
import hashlib
import json
from pathlib import Path
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
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


def main():
    raw = (ROOT / 'vectors/0.10.0/resolve02-scenarios.json').read_bytes()
    source = json.loads(raw)['cases'][0]
    observation = source['input']
    body = source['expected']['output']
    did = observation['did']
    origin = observation['policy']['configured_origin']
    url = origin + '/0.10.0/identifiers/' + quote(did, safe='')
    compact_size = len(json.dumps(body, separators=(',', ':')).encode())
    good = {
        'observation': observation,
        'request': {'method': 'GET', 'url': url,
                    'authenticated_tls_origin': origin,
                    'headers': {'X-SAGE-Version': '0.10.0',
                                'Accept': 'application/json'}},
        'response': {'status': 200, 'location': None, 'source': 'direct-origin',
                     'headers': {'X-SAGE-Version': '0.10.0',
                                 'Cache-Control': 'no-store',
                                 'Content-Type': 'application/json'},
                     'body': body, 'trailing_whitespace_bytes': 0,
                     'body_bytes': compact_size},
        'consumer_purpose': 'inspection'}
    wrong_media = copy.deepcopy(good)
    wrong_media['response']['headers']['Content-Type'] = 'application/did-resolution'
    redirect = copy.deepcopy(good)
    redirect['response']['status'] = 302
    redirect['response']['location'] = 'https://other.example/resolve'
    oversized = copy.deepcopy(good)
    oversized['response']['trailing_whitespace_bytes'] = 262145 - compact_size
    oversized['response']['body_bytes'] = 262145
    cached = copy.deepcopy(good)
    cached['response']['source'] = 'positive-cache'
    rows = [
        ('RESOLVE-05-P', good, 'ACCEPT', 'versioned uncached resolution envelope'),
        ('RESOLVE-05-N01', wrong_media, 'REJECT', 'unregistered resolution media type'),
        ('RESOLVE-05-N02', redirect, 'REJECT', 'redirect to another authority'),
        ('RESOLVE-05-N03', oversized, 'REJECT', 'wire response one byte over maximum'),
        ('RESOLVE-05-N04', cached, 'REJECT', 'positive response reused from cache'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': body if verdict == 'ACCEPT' else {},
                    'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime',
                   'input': {'operation': 'sage.did.http.resolve', 'input': inp},
                   'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    problem_cases = []
    for code, title, status in PROBLEMS:
        problem_cases.append({
            'code': code, 'http_status': status,
            'headers': {'X-SAGE-Version': '0.10.0',
                        'Cache-Control': 'no-store',
                        'Content-Type': 'application/problem+json'},
            'body': {'type': PROBLEM_BASE + code, 'title': title,
                     'status': status}})
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c',
             'resolution_source_sha256': hashlib.sha256(raw).hexdigest(),
             'scope': 'synthetic HTTP exchange; no live TLS, problem-type publication, independent RFC 9457 consumer, or authenticated Registry fetch',
             'cases': cases, 'problem_cases': problem_cases,
             'problem_type_publication': 'NOT_VERIFIED'}
    (ROOT / 'vectors/0.10.0/resolve05-scenarios.json').write_text(
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
