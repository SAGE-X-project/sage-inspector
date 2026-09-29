"""Revision-bound, host-facing contracts for cases without a local subject adapter.

These contracts check observation shape, rule identity, explicit source outcomes and
independent effect counts. They are partial inspection interfaces, never protocol
execution or implementation conformance evidence by themselves.
"""

from current_spec_catalog import require
from mcp_setup_model import initial as setup_initial, invariant as setup_invariant
from mcp_setup_model import step as setup_step


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


SERVER_SETUP = ('initialize', 'send_ok', 'initialized', 'send_ok',
                'list', 'send_ok')
MSET06_SCENARIOS = {
    'mset-06-before-deadline': (SERVER_SETUP[:-1] +
                                ('tick_29999', 'send_ok'), 'READY'),
    'mset-06-deadline-equality': (SERVER_SETUP[:-1] +
                                 ('tick_30000', 'send_ok'), 'CLOSED'),
    'mset-06-slow-callback': (SERVER_SETUP[:-1] +
                              ('tick_30000', 'send_ok', 'call_2'), 'CLOSED'),
    'mset-06-uncertain-send': (SERVER_SETUP[:-1] +
                               ('send_fail', 'send_ok'), 'CLOSED'),
    'mset-06-deadline-after-callback': (SERVER_SETUP[:-1] +
                                        ('tick_30000', 'send_ok'), 'CLOSED'),
    'mset-06-close-completion-race': (SERVER_SETUP[:-1] +
                                      ('close', 'send_ok'), 'CLOSED'),
    'mset-06-ready-past-setup-deadline': (SERVER_SETUP +
                                          ('tick_30001',), 'READY'),
}


def setup_model_check(ident, events):
    prescribed, phase = MSET06_SCENARIOS[ident]
    if type(events) is not list or events != list(prescribed):
        return False
    state = setup_initial('server')
    try:
        for event in events:
            after = setup_step(state, event)
            setup_invariant(state, event, after)
            state = after
    except (ValueError, AssertionError):
        return False
    return state.phase == phase and not state.admitted


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


def sample_observation(case, rule, track):
    ident = case['id']
    assertions = {name: True for name in assertions_for(rule['id'])
                  if not (ident in MSET06_SCENARIOS and
                          name == 'monotonic_deadline_checked')}
    result = {'case_id': ident, 'track': track,
              'observed_outcome': case['expected'], 'assertions': assertions,
              'observer_effects': 0, 'subject_effects': 0}
    if ident in MSET06_SCENARIOS:
        result['model_events'] = list(MSET06_SCENARIOS[ident][0])
    return result


def inspect(case, rule, track, phase, observed):
    if case['id'] == 'REG-08-N04':
        return expected_result(case['id'])
    fields = {'case_id', 'track', 'observed_outcome', 'assertions',
              'observer_effects', 'subject_effects'}
    if case['id'] in MSET06_SCENARIOS:
        fields.add('model_events')
    require(type(observed) is dict and
            set(observed) == fields and
            observed['case_id'] == case['id'] and observed['track'] == track and
            type(observed['observed_outcome']) is str and
            type(observed['assertions']) is dict and
            type(observed['observer_effects']) is int and
            type(observed['subject_effects']) is int and
            observed['observer_effects'] >= 0 and observed['subject_effects'] >= 0,
            'host observation shape and identity')
    required = tuple(name for name in assertions_for(rule['id'])
                     if not (case['id'] in MSET06_SCENARIOS and
                             name == 'monotonic_deadline_checked'))
    assertions_valid = (set(observed['assertions']) == set(required) and
                        all(observed['assertions'][key] is True for key in required))
    effects_agree = observed['observer_effects'] == observed['subject_effects']
    # Setup cannot dispatch any protected call. Other cases retain an explicit
    # independent counter agreement without guessing a normative effect count.
    setup_effects = phase != 4 or observed['observer_effects'] == 0
    model_ok = (case['id'] not in MSET06_SCENARIOS or
                setup_model_check(case['id'], observed['model_events']))
    matched = (observed['observed_outcome'] == expected_outcome(case) and
               assertions_valid and effects_agree and setup_effects and
               model_ok)
    return {'verdict': 'ACCEPT' if matched else 'REJECT',
            'output': {'matched': matched,
                       'reason': 'case_contract' if matched else
                                 'outcome_assertion_or_effect_mismatch'},
            'effects': {}}
