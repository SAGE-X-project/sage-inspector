"""Audit all remaining EXEC host contracts and their required tracks."""

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_host_probe import CONTRACTS, inspect, sample_observation
from generate_current_spec_host_contracts import SPEC, REVIEWS, cases


def check(root=ROOT):
    suite = load((root / 'vectors/0.10.0/exec-host-contracts.json').read_bytes())
    manifest, _, mapped = catalog(root)
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] ==
            manifest['source_sha256']['profiles/agent-mcp-security.md'] and
            len(suite['cases']) == 30 and len(CONTRACTS) == 15 and
            len(REVIEWS) == 15,
            'pinned host contract source and membership')
    for actual, (ident, track, inp, expected) in zip(suite['cases'], cases()):
        require(actual == {'id': ident, 'track': track,
                           'input': inp, 'expected': expected} and
                track in mapped[ident]['verification_tracks'],
                'host case and required track')
        relative = f'vectors/0.10.0/current-spec/{ident}-{track}.json'
        raw = (root / relative).read_bytes()
        require(load(raw) == {'schema_version': 1, 'spec_revision': SPEC,
                              'id': ident, 'track': track,
                              'input': inp, 'expected': expected} and
                any(row == {'id': ident, 'track': track,
                            'fixture': relative, 'fixture_sha256': sha(raw),
                            'coverage': 'partial'}
                    for row in bindings['bindings']),
                'host partial fixture binding')
        if track == 'runtime':
            facts = CONTRACTS[ident]['facts']
            positive = sample_observation(ident)
            require(inspect(ident, positive) == expected,
                    'safe host trace classification')
            if ident == 'EXEC-05-N05':
                require(facts['outcome'] == 'unknown' and
                        facts['claimed_rollback'] is False,
                        'committed cancellation uncertainty')
    require({ident for ident, *_ in cases()} == set(CONTRACTS) | set(REVIEWS) and
            all(not any(row['id'] == ident and row['track'] == 'document_review'
                        for row in bindings['bindings'])
                for ident in CONTRACTS),
            'host contract scope remains explicit')
    stage_one = [row for row in mapped.values()
                 if row['id'].startswith(('EXEC-', 'CST-01-', 'CST-02-',
                                          'mrevision-hop-')) or
                 row['id'] == 'mrevision-parent-no-grant']
    bound = {(row['id'], row['track']) for row in bindings['bindings']}
    require(len(stage_one) == 67 and
            all((row['id'], track) in bound for row in stage_one
                for track in row['verification_tracks']),
            'all first-stage required inspection tracks are bound')
    return len(suite['cases'])


if __name__ == '__main__':
    print(check())
