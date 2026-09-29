"""Audit fail-closed, zero-new-effect ledger-loss fixtures."""

from current_spec_catalog import ROOT, load, require, sha
from generate_current_spec_exec_lost_ledger_vectors import IDS, SPEC, cases


SOURCE = 'vectors/0.10.0/exec-lost-ledger.json'


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
            'ledger-loss source and identity')
    for case, (ident, inp, expected) in zip(suite['cases'], cases()):
        require(case == {'id': ident, 'input': inp, 'expected': expected} and
                inp['input']['configuration']['envelope_hex'] ==
                inp['input']['envelope_hex'] and
                expected['verdict'] == 'REJECT' and
                expected['effects'] == {'dispatch_before_loss': 1,
                                        'dispatch_after_loss': 0} and
                expected['output']['before_states'] ==
                ['RESERVED', 'EXECUTING'] and
                expected['output']['journal_recreated'] is False and
                expected['output']['retained_history_unchanged'] is True and
                expected['output']['post_loss_effects'] == 0,
                'one earlier inert handoff and fail-closed missing ledger')
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
                'missing-ledger partial binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
