"""Generate bounded local-diagnostic and public-failure fixtures."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('TABLE-07-P', 'TABLE-07-N01', 'TABLE-07-N02')
CODES = [
    'sig.missing', 'sig.malformed', 'sig.unknown-label', 'sig.base-mismatch',
    'sig.bad', 'sig.alg-mismatch', 'sig.stale', 'sig.replay', 'sig.coverage',
    'sig.binding', 'digest.missing', 'digest.mismatch', 'size.exceeded',
    'id.malformed', 'id.unknown-kind', 'record.not-found', 'record.inactive',
    'version.unsupported', 'record.stale', 'record.invalid', 'key.expired',
    'record.unreachable', 'key.not-in-record', 'key.unproven', 'key.revoked',
    'pop.bad', 'session.unknown', 'session.replay', 'session.window',
    'session.aead',
]


def main():
    good = {
        'channel': 'application-message', 'diagnostic_code': 'sig.bad',
        'local_log': {'code': 'sig.bad', 'event': 'authentication-rejected'},
        'public_response': {'status': 401,
                            'body': {'error': 'authentication_failed'}},
    }
    secret = copy.deepcopy(good)
    secret['local_log']['secret_material'] = 'fixture-only-canary'
    oracle = copy.deepcopy(good)
    oracle['public_response']['body']['reason'] = 'sig.bad'
    rows = [
        ('TABLE-07-P', good, 'ACCEPT', 'local diagnostic with generic public failure'),
        ('TABLE-07-N01', secret, 'REJECT', 'sensitive field recorded in local diagnostic'),
        ('TABLE-07-N02', oracle, 'REJECT', 'reason-specific public authentication oracle'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': {'public_status': 401} if verdict == 'ACCEPT' else {},
                    'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'runtime',
                   'input': {'operation': 'sage.diagnostic.application.boundary.check',
                             'input': inp}, 'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': {
                 'spec/11-registries.md': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
                 'spec/03-rfc9421.md': 'ca6b85e12a0b0e1a4f28b4eb2a9b677d29e2fd2abe9691d1ee30bfa14ee858c9',
                 'spec/08-transport.md': '87bb1adc1aae4883e13f8ba52a7c86153c71efb621ffc50458f7e2aa57db3eeb',
                 'spec/10-resolution.md': '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c'},
             'registered_codes': CODES,
             'scope': 'synthetic application diagnostic boundary; no live HTTP, log sink, timing-oracle, or resolution problem-detail claim',
             'cases': cases}
    (ROOT / 'vectors/0.10.0/table07-scenarios.json').write_text(
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
