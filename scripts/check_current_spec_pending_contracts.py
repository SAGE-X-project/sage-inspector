"""Audit phase-specific partial contracts and every required case track."""

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_evidence import load_bindings
from current_spec_pending_contracts import case_input, expected_result, inspect
from current_spec_pending_contracts import sample_observation
from generate_current_spec_pending_contracts import COUNTS


def check(phase, root=ROOT):
    require(phase in COUNTS, 'pending phase')
    manifest, source, mapped = catalog(root)
    suite = load((root / f'vectors/0.10.0/current-spec-phase-{phase}-contracts.json').read_bytes())
    require(suite['schema_version'] == 1 and
            suite['spec_revision'] == manifest['spec_revision'] and
            suite['phase'] == phase and
            suite['source_sha256'] == manifest['source_sha256'] and
            len(suite['parent_case_ids']) == COUNTS[phase][0],
            'pending suite identity')
    cases = {row['id']: row for row in source['cases']}
    children = {row['id']: row for row in source['mandatory_subscenarios']}
    rules = {row['id']: row for row in source['rules']}
    bindings = load_bindings(root, manifest['spec_revision'], mapped, children)
    require(len(suite['cases']) == (COUNTS[phase][1] or len(suite['cases'])),
            'pending track count')
    for row in suite['cases']:
        ident, track = row['id'], row['track']
        case = cases.get(ident, children.get(ident))
        rule = rules[case['rule_id']] if ident in cases else rules['MOWN-06']
        inp = case_input(case, rule, track, phase)
        expected = expected_result(ident)
        require(row['input'] == inp and row['expected'] == expected and
                bindings[(ident, track)][1]['input'] == inp and
                bindings[(ident, track)][1]['expected'] == expected and
                bindings[(ident, track)][0]['coverage'] == 'partial',
                'pending contract fixture: ' + ident)
        good = sample_observation(case, rule, track)
        require(inspect(case, rule, track, phase, good) == expected,
                'safe positive trace: ' + ident)
        changed = dict(good, subject_effects=1)
        require(inspect(case, rule, track, phase, changed)['verdict'] == 'REJECT',
                'independent effect divergence: ' + ident)
    require(len({row['id'] for row in suite['cases'] if row['id'] in cases}) ==
            COUNTS[phase][0], 'pending parent membership')
    return len(suite['cases'])


if __name__ == '__main__':
    import sys
    print(check(int(sys.argv[1])))
