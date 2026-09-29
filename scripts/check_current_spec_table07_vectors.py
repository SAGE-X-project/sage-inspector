"""Independently audit local diagnostics versus public authentication failures."""

import copy

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/table07-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('TABLE-07-P', 'TABLE-07-N01', 'TABLE-07-N02')
HASHES = {
    'spec/11-registries.md': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
    'spec/03-rfc9421.md': 'ca6b85e12a0b0e1a4f28b4eb2a9b677d29e2fd2abe9691d1ee30bfa14ee858c9',
    'spec/08-transport.md': '87bb1adc1aae4883e13f8ba52a7c86153c71efb621ffc50458f7e2aa57db3eeb',
    'spec/10-resolution.md': '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c',
}
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
PUBLIC = {'status': 401, 'body': {'error': 'authentication_failed'}}
POSITIVE = {'channel': 'application-message', 'diagnostic_code': 'sig.bad',
            'local_log': {'code': 'sig.bad',
                          'event': 'authentication-rejected'},
            'public_response': PUBLIC}


def decision(inp):
    if type(inp) is not dict or set(inp) != {
            'channel', 'diagnostic_code', 'local_log', 'public_response'}:
        return 'REJECT'
    code, log, response = (inp['diagnostic_code'], inp['local_log'],
                           inp['public_response'])
    if (inp['channel'] != 'application-message' or type(code) is not str or
            code not in CODES or type(log) is not dict or
            log != {'code': code, 'event': 'authentication-rejected'} or
            response != PUBLIC):
        return 'REJECT'
    return 'ACCEPT'


def check(root=ROOT):
    data = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(data['schema_version'] == 1 and data['spec_revision'] == SPEC and
            data['source_sha256'] == HASHES and
            all(manifest['source_sha256'][path] == digest for path, digest in HASHES.items()) and
            data['registered_codes'] == CODES and len(CODES) == len(set(CODES)) == 30 and
            data['scope'] == 'synthetic application diagnostic boundary; no live HTTP, log sink, timing-oracle, or resolution problem-detail claim' and
            tuple(row['id'] for row in data['cases']) == IDS,
            'pinned TABLE-07 source identities and thirty distinct diagnostic codes')
    good, secret, oracle = [row['input'] for row in data['cases']]
    require(good == POSITIVE and decision(good) == 'ACCEPT' and
            secret == dict(good, local_log=dict(good['local_log'],
                                                secret_material='fixture-only-canary')) and
            oracle == dict(good, public_response={
                'status': 401,
                'body': {'error': 'authentication_failed', 'reason': 'sig.bad'}}),
            'isolated sensitive diagnostic and public reason-oracle defects')
    for index, row in enumerate(data['cases']):
        ident = row['id']
        expected = {'verdict': 'ACCEPT' if index == 0 else 'REJECT',
                    'output': {'public_status': 401} if index == 0 else {},
                    'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(decision(row['input']) == expected['verdict'] and
                row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.diagnostic.application.boundary.check',
                                      'input': row['input']}, 'expected': expected},
                'TABLE-07 case contract: ' + ident)
    controls = []
    for code in ('sig.bad', 'sig.replay', 'key.revoked', 'session.aead'):
        changed = copy.deepcopy(good)
        changed['diagnostic_code'] = code
        changed['local_log']['code'] = code
        controls.append((code + '-generic-response', changed, 'ACCEPT'))
    for name, path, value in (
        ('unknown-code', ('diagnostic_code',), 'sig.hidden-test'),
        ('local-code-mismatch', ('local_log', 'code'), 'key.revoked'),
        ('private-key-field', ('local_log', 'secret_material'), 'fixture-only-canary'),
        ('full-payload-field', ('local_log', 'request_payload'), 'fixture-only-canary'),
        ('public-reason', ('public_response', 'body', 'reason'), 'sig.bad'),
        ('reason-dependent-status', ('public_response', 'status'), 403),
        ('public-code-field', ('public_response', 'body', 'code'), 'sig.bad'),
        ('public-diagnostic-header', ('public_response', 'diagnostic'), 'sig.bad'),
    ):
        changed = copy.deepcopy(good)
        node = changed
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value
        controls.append((name, changed, 'REJECT'))
    require(all(decision(inp) == expected for _, inp, expected in controls),
            'independent generic failure, log minimization, and oracle controls')
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(all(any(binding['id'] == ident and binding['track'] == 'runtime' and
                    binding['coverage'] == 'partial' and
                    binding['fixture_sha256'] == sha((root / 'vectors/0.10.0/current-spec' /
                                                     (ident + '.json')).read_bytes())
                    for binding in bindings['bindings']) for ident in IDS),
            'partial runtime case bindings')
    return len(IDS), len(CODES), len(controls)


if __name__ == '__main__':
    print(check())
