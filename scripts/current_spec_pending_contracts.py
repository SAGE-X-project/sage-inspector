"""Revision-bound, host-facing contracts for cases without a local subject adapter.

These contracts check observation shape, rule identity, explicit source outcomes and
independent effect counts. They are partial inspection interfaces, never protocol
execution or implementation conformance evidence by themselves.
"""

import json
import uuid

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
SETUP_MODEL_SCENARIOS = {
    **MSET06_SCENARIOS,
    'mset-02-output-barrier': (('initialize', 'call_2'), 'CLOSED'),
    'mset-02-send-failure-after-prepare':
        (('initialize', 'initialized', 'send_fail'), 'CLOSED'),
    'mset-02-setup-id-reuse': (SERVER_SETUP + ('call_0',), 'CLOSED'),
    'mset-02-history-exhaustion': (SERVER_SETUP + ('call_2',), 'CLOSED'),
    'mset-02-inner-rejection-replay':
        (('bad_inner', 'initialize'), 'CLOSED'),
    'mset-05-early-tool-call':
        (SERVER_SETUP[:2] + ('call_2',), 'CLOSED'),
    'mset-07-stale-ready': (SERVER_SETUP + ('close', 'call_2'), 'CLOSED'),
}
MSET03_SCENARIOS = {
    'mset-03-initialize-success': 'valid',
    'mset-03-unsupported-version': 'unsupported_version',
    'mset-03-capability-mismatch': 'capability_mismatch',
    'mset-03-wrong-request': 'wrong_request',
}


def canonical_uuid4(value):
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return parsed.version == 4 and str(parsed) == value


def unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON member')
        value[key] = item
    return value


def mset03_classification(evidence):
    require(type(evidence) is dict and
            set(evidence) == {'outer_request_id', 'inner_request_id',
                              'response_outer_id', 'response_json',
                              'outer_success', 'outer_error'} and
            all(canonical_uuid4(evidence[key]) for key in
                ('outer_request_id', 'inner_request_id',
                 'response_outer_id')) and
            evidence['outer_request_id'] != evidence['inner_request_id'] and
            type(evidence['response_json']) is str and
            len(evidence['response_json'].encode()) <= 16 * 1024 and
            type(evidence['outer_success']) is bool and
            (evidence['outer_error'] is None or
             type(evidence['outer_error']) is str and
             len(evidence['outer_error']) <= 128),
            'bounded authenticated initialize response')
    try:
        inner = json.loads(evidence['response_json'],
                           object_pairs_hook=unique_json_object)
    except (ValueError, TypeError):
        return 'malformed_response'
    if type(inner) is not dict or set(inner) != {'jsonrpc', 'id', 'result'} or \
            inner['jsonrpc'] != '2.0' or type(inner['result']) is not dict:
        return 'malformed_response'
    if evidence['response_outer_id'] != evidence['outer_request_id'] or \
            inner['id'] != evidence['inner_request_id']:
        return 'wrong_request'
    if not evidence['outer_success'] or evidence['outer_error'] is not None:
        return 'outer_failure'
    result = inner['result']
    if set(result) != {'protocolVersion', 'serverInfo', 'capabilities'} or \
            type(result['serverInfo']) is not dict or \
            set(result['serverInfo']) != {'name', 'version'} or \
            not all(type(value) is str and 1 <= len(value) <= 128
                    for value in result['serverInfo'].values()):
        return 'malformed_response'
    if result['protocolVersion'] != '2025-06-18':
        return 'unsupported_version'
    if result['capabilities'] != {'tools': {}}:
        return 'capability_mismatch'
    return 'valid'


def mset03_sample(ident):
    outer = '123e4567-e89b-42d3-a456-426614174000'
    inner = '123e4567-e89b-42d3-a456-426614174001'
    response = {'jsonrpc': '2.0', 'id': inner,
                'result': {'protocolVersion': '2025-06-18',
                           'serverInfo': {'name': 'local-fixture', 'version': '1'},
                           'capabilities': {'tools': {}}}}
    evidence = {'outer_request_id': outer, 'inner_request_id': inner,
                'response_outer_id': outer, 'outer_success': True,
                'outer_error': None}
    if ident == 'mset-03-unsupported-version':
        response['result']['protocolVersion'] = '2024-11-05'
    elif ident == 'mset-03-capability-mismatch':
        response['result']['capabilities'] = {'resources': {}}
    elif ident == 'mset-03-wrong-request':
        response['id'] = '123e4567-e89b-42d3-a456-426614174002'
    evidence['response_json'] = json.dumps(response, separators=(',', ':'))
    return evidence


def setup_model_check(ident, events):
    prescribed, phase = SETUP_MODEL_SCENARIOS[ident]
    if type(events) is not list or events != list(prescribed):
        return False
    state = setup_initial('server')
    try:
        for event in events:
            after = setup_step(state, event,
                               2 if ident == 'mset-02-history-exhaustion' else 3)
            setup_invariant(state, event, after)
            state = after
    except (ValueError, AssertionError):
        return False
    return (state.phase == phase and not state.admitted and
            (ident != 'mset-02-inner-rejection-replay' or state.replay != 0))


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
                          name == 'monotonic_deadline_checked') and
                  not (ident in MSET03_SCENARIOS and
                       name == 'initialize_correlation_checked')}
    result = {'case_id': ident, 'track': track,
              'observed_outcome': case['expected'], 'assertions': assertions,
              'observer_effects': 0, 'subject_effects': 0}
    if ident in SETUP_MODEL_SCENARIOS:
        result['model_events'] = list(SETUP_MODEL_SCENARIOS[ident][0])
    if ident in MSET03_SCENARIOS:
        result['mcp_response'] = mset03_sample(ident)
    return result


def inspect(case, rule, track, phase, observed):
    if case['id'] == 'REG-08-N04':
        return expected_result(case['id'])
    fields = {'case_id', 'track', 'observed_outcome', 'assertions',
              'observer_effects', 'subject_effects'}
    if case['id'] in SETUP_MODEL_SCENARIOS:
        fields.add('model_events')
    if case['id'] in MSET03_SCENARIOS:
        fields.add('mcp_response')
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
                             name == 'monotonic_deadline_checked') and
                     not (case['id'] in MSET03_SCENARIOS and
                          name == 'initialize_correlation_checked'))
    assertions_valid = (set(observed['assertions']) == set(required) and
                        all(observed['assertions'][key] is True for key in required))
    effects_agree = observed['observer_effects'] == observed['subject_effects']
    # Setup cannot dispatch any protected call. Other cases retain an explicit
    # independent counter agreement without guessing a normative effect count.
    setup_effects = phase != 4 or observed['observer_effects'] == 0
    model_ok = (case['id'] not in SETUP_MODEL_SCENARIOS or
                setup_model_check(case['id'], observed['model_events']))
    mcp_response_ok = (case['id'] not in MSET03_SCENARIOS or
                       mset03_classification(observed['mcp_response']) ==
                       MSET03_SCENARIOS[case['id']])
    matched = (observed['observed_outcome'] == expected_outcome(case) and
               assertions_valid and effects_agree and setup_effects and
               model_ok and mcp_response_ok)
    return {'verdict': 'ACCEPT' if matched else 'REJECT',
            'output': {'matched': matched,
                       'reason': 'case_contract' if matched else
                                 'outcome_assertion_or_effect_mismatch'},
            'effects': {}}
