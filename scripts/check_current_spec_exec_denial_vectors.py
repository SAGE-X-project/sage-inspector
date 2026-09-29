"""Independently audit policy, resolver and retirement denial fixtures."""

from current_spec_catalog import ROOT, load, require, sha
from generate_current_spec_exec_denial_vectors import IDS, SPEC, cases


SOURCE = 'vectors/0.10.0/exec-denials.json'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] ==
            manifest['source_sha256']['profiles/agent-mcp-security.md'] and
            suite['historical_bytes_sha256'] ==
            sha((root / 'vectors/0.10.0/guard-records.json').read_bytes()) ==
            '68bd8c57a9a572849ea5f57f77d93c0e7d2fe813ea7b158c47b24c832efdef0f' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'pinned denial source and case identities')
    base = suite['cases'][2]['input']['input']['stages'][0]['actions']
    policy = suite['cases'][0]['input']['input']['stages'][0]['actions']
    resolver = suite['cases'][1]['input']['input']['stages'][0]['actions']
    require(policy[0]['input']['policy_allow'] is False and
            resolver[0]['input']['active_key'] is False and
            policy[0]['input']['active_key'] is True and
            resolver[0]['input']['policy_allow'] is True and
            [row['action'] for row in base] ==
            ['configure', 'retire', 'dispatch'] and
            policy[1] == resolver[1] == base[2] and
            policy[0]['input']['envelope_hex'] ==
            resolver[0]['input']['envelope_hex'] ==
            base[0]['input']['envelope_hex'],
            'one changed trusted control and one exact signed intent')
    for case, (ident, inp, expected) in zip(suite['cases'], cases()):
        require(case == {'id': ident, 'input': inp, 'expected': expected} and
                expected['verdict'] == 'REJECT' and
                expected['effects'] == {'dispatch': 0} and
                expected['output']['journal_states'] == [] and
                all(row['effect_sha256'] == []
                    for row in expected['output']['stages'][0]) and
                expected['output']['stages'][0][-1]['ok'] is False,
                'zero-effect denial expectation: ' + ident)
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': inp, 'expected': expected} and
                any(row == {'id': ident, 'track': 'runtime',
                            'fixture': path,
                            'fixture_sha256': sha((root / path).read_bytes()),
                            'coverage': 'partial'}
                    for row in bindings['bindings']),
                'partial current-case binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
