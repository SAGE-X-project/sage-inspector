"""Revision-bound, host-facing contracts for cases without a local subject adapter.

These contracts check observation shape, rule identity, explicit source outcomes and
independent effect counts. They are partial inspection interfaces, never protocol
execution or implementation conformance evidence by themselves.
"""

from current_spec_catalog import require


RULE_ASSERTIONS = {
    'MSET-01': ('authenticated_channel', 'session_owner_bound'),
    'MSET-02': ('outer_carriage_checked', 'replay_history_preserved'),
    'MSET-03': ('initialize_correlation_checked',),
    'MSET-04': ('notification_ack_checked',),
    'MSET-05': ('descriptor_and_gate_checked',),
    'MSET-06': ('monotonic_deadline_checked',),
    'MSET-07': ('fresh_owner_and_durable_state_checked',),
    'MSET-08': ('profile_scope_checked',),
    'MOWN-01': ('ownership_boundary_checked',),
    'MOWN-02': ('owner_publication_checked',),
    'MOWN-03': ('reservation_fence_checked',),
    'MOWN-04': ('closure_and_deadline_checked',),
    'MOWN-05': ('signature_role_checked',),
    'MOWN-06': ('mandatory_child_boundary_checked',),
}


def assertions_for(rule_id):
    return RULE_ASSERTIONS.get(rule_id, ('normative_boundary_checked',))


def expected_outcome(case):
    return case['expected']


def case_input(case, rule, track, phase):
    trigger = case.get('input', case.get('scenario'))
    return {'operation': 'sage.spec.host_case',
            'phase': phase, 'id': case['id'], 'track': track,
            'rule_id': rule['id'], 'source': rule['source'],
            'source_line': rule['line'], 'trigger': trigger,
            'preconditions': case.get('preconditions', case.get('planned_method'))}


def expected_result(ident=None):
    if ident == 'REG-08-N04':
        return {'verdict': 'REJECT',
                'output': {'matched': False, 'reason': 'spec_underspecified'},
                'effects': {}}
    return {'verdict': 'ACCEPT',
            'output': {'matched': True, 'reason': 'case_contract'}, 'effects': {}}


def inspect(case, rule, track, phase, observed):
    if case['id'] == 'REG-08-N04':
        return expected_result(case['id'])
    require(type(observed) is dict and
            set(observed) == {'case_id', 'track', 'observed_outcome',
                              'assertions', 'observer_effects', 'subject_effects'} and
            observed['case_id'] == case['id'] and observed['track'] == track and
            type(observed['observed_outcome']) is str and
            type(observed['assertions']) is dict and
            type(observed['observer_effects']) is int and
            type(observed['subject_effects']) is int and
            observed['observer_effects'] >= 0 and observed['subject_effects'] >= 0,
            'host observation shape and identity')
    required = assertions_for(rule['id'])
    assertions_valid = (set(observed['assertions']) == set(required) and
                        all(observed['assertions'][key] is True for key in required))
    effects_agree = observed['observer_effects'] == observed['subject_effects']
    # Setup cannot dispatch any protected call. Other cases retain an explicit
    # independent counter agreement without guessing a normative effect count.
    setup_effects = phase != 4 or observed['observer_effects'] == 0
    matched = (observed['observed_outcome'] == expected_outcome(case) and
               assertions_valid and effects_agree and setup_effects)
    return {'verdict': 'ACCEPT' if matched else 'REJECT',
            'output': {'matched': matched,
                       'reason': 'case_contract' if matched else
                                 'outcome_assertion_or_effect_mismatch'},
            'effects': {}}
