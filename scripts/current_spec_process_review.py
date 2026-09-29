"""Independent process-rule checks over the pinned specification inventory."""

from current_spec_catalog import require


IDS = (
    'PROC-01-P', 'PROC-01-N01', 'PROC-01-N02',
    'PROC-02-P', 'PROC-02-N01', 'PROC-02-N02',
    'PROC-03-P', 'PROC-03-N01', 'PROC-03-N02',
)


def mapped_rules(trace):
    requirements = {row['id']: row for row in trace['requirements']}
    cases = {row['id']: row for row in trace['cases']}
    rules = {row['id']: row for row in trace['rules']}
    if len(requirements) != len(trace['requirements']) or \
            len(cases) != len(trace['cases']) or \
            len(rules) != len(trace['rules']) or \
            not all(row['rule_ids'] for row in requirements.values()) or \
            not all(row['rule_id'] in rules for row in cases.values()):
        return False
    for rid, rule in rules.items():
        if not rule['requirements'] or any(q not in requirements for q in rule['requirements']):
            return False
        if rule.get('mapping_kind') != 'mandatory_child_assertions' and \
                set(rule['case_ids']) != {cid for cid, row in cases.items()
                                         if row['rule_id'] == rid}:
            return False
    return all(set(req['rule_ids']) ==
               {rid for rid, rule in rules.items() if qid in rule['requirements']}
               for qid, req in requirements.items())


def evaluate(ident, configuration, trace, old_revision, current_revision):
    require(ident in IDS and type(configuration) is dict and
            type(trace) is dict and type(old_revision) is str and
            type(current_revision) is str and old_revision != current_revision,
            'process review inputs')
    kind = ident[:7]
    if kind == 'PROC-01':
        require(set(configuration) == {'source_of_truth', 'remove_case_mapping'},
                'source review fields')
        case_map = configuration['remove_case_mapping']
        require(type(case_map) is bool and
                configuration['source_of_truth'] in ('normative_text', 'implementation'),
                'source review values')
        if case_map:
            # The mutation is in-memory, never written back to the pinned trace.
            from copy import deepcopy
            trace = deepcopy(trace)
            rule = next(row for row in trace['rules']
                        if row['case_ids'] and
                        row.get('mapping_kind') != 'mandatory_child_assertions')
            rule['case_ids'].pop()
        accepted = mapped_rules(trace) and \
            configuration['source_of_truth'] == 'normative_text'
        reason = 'normative_mapping' if accepted else 'mapping_or_source_conflict'
    elif kind == 'PROC-02':
        require(set(configuration) == {'vector_revision', 'observation_present',
                                       'claimed_status'}, 'evidence review fields')
        require(configuration['vector_revision'] in (old_revision, current_revision)
                and type(configuration['observation_present']) is bool and
                configuration['claimed_status'] in ('PASS', 'NOT_RUN'),
                'evidence review values')
        accepted = (configuration['vector_revision'] == old_revision and
                    (configuration['claimed_status'] != 'PASS' or
                     configuration['observation_present']))
        reason = 'revision_bound_evidence' if accepted else 'false_evidence_promotion'
    else:
        require(set(configuration) == {'canonical_sources', 'touched_repositories'},
                'repository review fields')
        sources = configuration['canonical_sources']
        touched = configuration['touched_repositories']
        require(type(sources) is list and type(touched) is list and
                all(type(value) is str for value in sources + touched),
                'repository review values')
        accepted = (sources == ['spec/', 'profiles/', 'charter.md'] and
                    set(touched) <= {'sage-inspector', 'sage-spec'})
        reason = 'single_specification_owner' if accepted else 'competing_source_or_code_change'
    return {'verdict': 'ACCEPT' if accepted else 'REJECT',
            'output': {'accepted': accepted, 'reason': reason},
            'effects': {}}
