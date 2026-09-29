"""Independently audit the limited Execution Guard claim review cases."""

from current_spec_catalog import ROOT, load, require, sha


SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-09-P', 'EXEC-09-N01', 'EXEC-09-N02')
SOURCE = 'vectors/0.10.0/exec09-claims.json'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == manifest['source_sha256'][
                'profiles/agent-mcp-security.md'] and
            suite['scope'] == 'synthetic claim declarations only; no review of actual product wording or external attestation' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'EXEC-09 source and review scope')
    expected = (
        {'claim': 'authenticated-execution-intent',
         'basis': ['valid-signature', 'trusted-authorization-policy',
                   'enforced-dispatch-boundary'],
         'scope': 'approved-intent-only'},
        {'claim': 'semantic-safety', 'basis': ['valid-signature'],
         'scope': 'all-model-decisions'},
        {'claim': 'whole-host-integrity', 'basis': ['file-hash'],
         'scope': 'entire-host'},
    )
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    for index, row in enumerate(suite['cases']):
        ident = IDS[index]
        outcome = {'verdict': 'ACCEPT' if index == 0 else 'REJECT',
                   'output': {}, 'effects': {}}
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(row['input'] == expected[index] and
                row['expected'] == outcome and fixture == {
                    'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                    'track': 'document_review',
                    'input': {'review_type': 'security_claim_scope',
                              'declaration': expected[index]},
                    'expected': outcome},
                'EXEC-09 case contract: ' + ident)
        require(any(binding == {'id': ident, 'track': 'document_review',
                                'fixture': path,
                                'fixture_sha256': sha((root / path).read_bytes()),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'EXEC-09 partial document binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
