"""Audit phase-specific partial contracts and every required case track."""

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_evidence import load_bindings
from current_spec_pending_contracts import case_input, expected_result, inspect
from current_spec_pending_contracts import SEMANTIC_MSET_IDS
from current_spec_pending_contracts import SEMANTIC_MOWN_PARENT_IDS
from current_spec_pending_contracts import MOWN06_CHILD_IDS
from current_spec_pending_contracts import sample_observation
from current_spec_remaining_overview import IDS as OVERVIEW_IDS
from current_spec_remaining_crypto import IDS as CRYPTO_IDS
from current_spec_remaining_hpke import SAMPLES as HPKE05_SAMPLES
from current_spec_remaining_registry import IDS as REGISTRY_IDS
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
    if phase == 4:
        require(set(suite['parent_case_ids']) == SEMANTIC_MSET_IDS and
                len(SEMANTIC_MSET_IDS) == 43,
                'every setup parent has a semantic review path')
    if phase == 5:
        require(set(suite['parent_case_ids']) == SEMANTIC_MOWN_PARENT_IDS and
                len(SEMANTIC_MOWN_PARENT_IDS) == 37,
                'every owner parent has a semantic review path')
        require({row['id'] for row in suite['cases'] if row['id'] in children} ==
                MOWN06_CHILD_IDS and len(MOWN06_CHILD_IDS) == 26,
                'every mandatory owner child has a semantic review path')
    if phase == 6:
        semantic_ids = (set(OVERVIEW_IDS) | set(CRYPTO_IDS) |
                        set(HPKE05_SAMPLES) | set(REGISTRY_IDS))
        require(len(semantic_ids) == 50 and
                set(suite['parent_case_ids']) ==
                semantic_ids | {'REG-08-N04'},
                'every decidable remaining parent has a semantic review path')
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
