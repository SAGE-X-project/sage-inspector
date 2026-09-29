"""Add pinned partial host contracts in the prescribed MSET, MOWN, gap order."""

import argparse
import json
from pathlib import Path

from current_spec_catalog import ROOT, catalog, sha
from current_spec_evidence import load_bindings
from current_spec_pending_contracts import case_input, expected_result


COUNTS = {4: (43, 46), 5: (37, 63), 6: (51, None)}


def selected(root, phase):
    manifest, trace, mapped = catalog(root)
    rules = {rule['id']: rule for rule in trace['rules']}
    children = {row['id']: row for row in trace['mandatory_subscenarios']}
    bindings = load_bindings(root, manifest['spec_revision'], mapped, children)
    cases = []
    suite_path = root / f'vectors/0.10.0/current-spec-phase-{phase}-contracts.json'
    prior = json.loads(suite_path.read_text()) if suite_path.exists() else None
    if phase in (4, 5):
        prefix = 'MSET-' if phase == 4 else 'MOWN-'
        cases = [case for case in trace['cases']
                 if case['rule_id'].startswith(prefix)]
    elif prior is not None:
        by_id = {case['id']: case for case in trace['cases']}
        cases = [by_id[ident] for ident in prior['parent_case_ids']]
    else:
        cases = [case for case in trace['cases']
                 if not case['rule_id'].startswith(('MSET-', 'MOWN-')) and
                 any((case['id'], track) not in bindings
                     for track in mapped[case['id']]['verification_tracks'])]
    assert len(cases) == COUNTS[phase][0], (phase, len(cases))
    rows = []
    prior_keys = ({(row['id'], row['track']) for row in prior['cases']}
                  if prior is not None else None)
    for case in cases:
        for track in mapped[case['id']]['verification_tracks']:
            if ((case['id'], track) in prior_keys if prior_keys is not None
                    else (case['id'], track) not in bindings):
                rows.append((case, rules[case['rule_id']], track))
    if phase == 5:
        rule = rules['MOWN-06']
        for child in trace['mandatory_subscenarios']:
            if (prior_keys is not None or
                    (child['id'], 'runtime') not in bindings):
                rows.append((child, rule, 'runtime'))
    assert COUNTS[phase][1] is None or len(rows) == COUNTS[phase][1], (phase, len(rows))
    return manifest, trace, mapped, bindings, cases, rows


def generate(root, phase):
    manifest, trace, mapped, bindings, cases, rows = selected(root, phase)
    path = root / 'verification/0.10.0/current-spec/bindings.json'
    contract = json.loads(path.read_text())
    owned = {(case['id'], track) for case, _, track in rows}
    contract['bindings'] = [row for row in contract['bindings']
                            if (row['id'], row['track']) not in owned]
    suite = {'schema_version': 1, 'spec_revision': manifest['spec_revision'],
             'phase': phase, 'parent_case_ids': [case['id'] for case in cases],
             'source_sha256': manifest['source_sha256'],
             'scope': 'partial host observation contracts; no implementation run or full conformance claim',
             'cases': []}
    for case, rule, track in rows:
        ident = case['id']
        inp = case_input(case, rule, track, phase)
        expected = expected_result(ident)
        fixture = {'schema_version': 1, 'spec_revision': manifest['spec_revision'],
                   'id': ident, 'track': track,
                   'input': inp, 'expected': expected}
        relative = f'vectors/0.10.0/current-spec/{ident}-{track}.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (root / relative).write_bytes(raw)
        contract['bindings'].append({'id': ident, 'track': track,
                                     'fixture': relative, 'fixture_sha256': sha(raw),
                                     'coverage': 'partial'})
        suite['cases'].append({'id': ident, 'track': track,
                               'input': inp, 'expected': expected})
    (root / f'vectors/0.10.0/current-spec-phase-{phase}-contracts.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(contract, indent=2) + '\n')
    return len(cases), len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', type=int, choices=COUNTS)
    args = parser.parse_args()
    print(generate(ROOT, args.phase))


if __name__ == '__main__':
    main()
