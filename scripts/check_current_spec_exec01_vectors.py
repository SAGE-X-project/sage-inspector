"""Audit independent EXEC-01 review examples and their partial bindings."""

import copy

from current_spec_catalog import ROOT, load, require, sha


SPEC = '5bcf511e604579afa63f434013447f44b6858828'
SOURCE = 'vectors/0.10.0/exec01-review-scenarios.json'
IDS = ('EXEC-01-P', 'EXEC-01-N01', 'EXEC-01-N02',
       'EXEC-01-N03', 'EXEC-01-N04')
PATHS = {'subprocess', 'network', 'file', 'retry', 'parallel', 'subagent'}
ASSETS = {'original_request', 'policy', 'signing_key',
          'component_manifest', 'verifier', 'dispatch_gate'}


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == manifest['source_sha256'][
                'profiles/agent-mcp-security.md'] and
            suite['source'] == 'profiles/agent-mcp-security.md#1-protection-and-trust-boundary--exec-01' and
            suite['scope'] == 'synthetic capability description only; no host isolation or deployment conformance claim' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'EXEC-01 source, scope, or case identity')
    good, key, verifier, bypass, hook = [row['input'] for row in suite['cases']]
    require(set(good) == {'untrusted_principals', 'protected_assets',
                          'effect_paths', 'hook', 'server'} and
            set(good['untrusted_principals']) == {'plugin', 'skill', 'mcp',
                                                  'model', 'child'} and
            set(good['protected_assets']) == ASSETS and
            set(good['effect_paths']) == PATHS and
            all(value == {'mediated_by': 'trusted_dispatch_gate',
                          'bypass_credentials_exposed': False}
                for value in good['effect_paths'].values()) and
            good['server'] == {'verifier_boundary': 'trusted_server',
                               'dispatcher_boundary': 'trusted_server',
                               'tool_boundary': 'isolated_untrusted',
                               'tool_has_host_privilege': False},
            'positive capability contract')
    for defective, path, value in (
        (key, ('protected_assets', 'signing_key', 'readers'),
         ['trusted_client', 'plugin']),
        (verifier, ('protected_assets', 'verifier', 'writers'),
         ['trusted_admin', 'plugin']),
        (bypass, ('effect_paths', 'subprocess', 'mediated_by'),
         'untrusted_plugin'),
        (hook, ('hook', 'mandatory'), False),
    ):
        clone = copy.deepcopy(good)
        node = clone
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value
        require(defective == clone, 'negative fixture must change one boundary')
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    for index, row in enumerate(suite['cases']):
        ident = IDS[index]
        expected = {'verdict': 'ACCEPT' if index == 0 else 'REJECT',
                    'output': {}, 'effects': {}}
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(row['expected'] == expected and fixture == {
            'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
            'track': 'deployment_review',
            'input': {'review_type': 'execution_guard_capability_boundary',
                      'synthetic_description': row['input']},
            'expected': expected}, 'EXEC-01 fixture contract: ' + ident)
        require(any(binding == {'id': ident, 'track': 'deployment_review',
                                'fixture': path,
                                'fixture_sha256': sha((root / path).read_bytes()),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'EXEC-01 partial review binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
