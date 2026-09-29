"""Typed, inert observations for Execution Guard host-only boundaries.

This is an inspection contract, not a host implementation or conformance
evidence. An external version-pinned host adapter must produce the observations.
"""

from current_spec_catalog import require


# Every row names only externally observable facts. No executable bypass,
# arbitrary signer, mutable loader, or network probe is constructed here.
CONTRACTS = {
    'EXEC-01-P': {
        'trigger': 'protected_authorized_effect',
        'facts': {'trusted_gate_called': True, 'capability_isolated': True,
                  'new_effects': 1, 'outcome': 'allowed'}},
    'EXEC-01-N01': {
        'trigger': 'plugin_attempts_key_read',
        'facts': {'key_read_succeeded': False, 'new_effects': 0,
                  'outcome': 'denied'}},
    'EXEC-01-N02': {
        'trigger': 'plugin_attempts_verifier_replacement',
        'facts': {'verifier_replaced': False, 'trusted_gate_called': True,
                  'new_effects': 0, 'outcome': 'denied'}},
    'EXEC-01-N03': {
        'trigger': 'untrusted_direct_effect_attempt',
        'facts': {'unmediated_effects': 0, 'new_effects': 0,
                  'outcome': 'denied'}},
    'EXEC-01-N04': {
        'trigger': 'required_hook_disabled',
        'facts': {'hook_disabled': True,
                  'protected_profile_advertised': False,
                  'new_effects': 0, 'outcome': 'unsupported'}},
    'EXEC-02-N02': {
        'trigger': 'unchecked_model_proposal',
        'facts': {'proposal_checked': False, 'signed_intents': 0,
                  'new_effects': 0, 'outcome': 'denied'}},
    'EXEC-04-N04': {
        'trigger': 'arguments_change_before_dispatch',
        'facts': {'verified_bytes_equal_final_bytes': False,
                  'new_effects': 0, 'outcome': 'denied'}},
    'EXEC-05-N05': {
        'trigger': 'cancel_after_commit',
        'facts': {'commit_observed': True, 'cancel_observed': True,
                  'claimed_rollback': False, 'new_effects': 0,
                  'outcome': 'unknown'}},
    'EXEC-06-N01': {
        'trigger': 'untrusted_baseline_write',
        'facts': {'authenticated_admin_update': False,
                  'baseline_changed': False, 'new_effects': 0,
                  'outcome': 'denied'}},
    'EXEC-06-N02': {
        'trigger': 'symbolic_link_artifact',
        'facts': {'artifact_is_symlink': True, 'loaded_artifacts': 0,
                  'new_effects': 0, 'outcome': 'denied'}},
    'EXEC-06-N04': {
        'trigger': 'artifact_changes_after_measurement',
        'facts': {'measured_instance_equal_loaded_instance': False,
                  'loaded_artifacts': 0, 'new_effects': 0,
                  'outcome': 'denied'}},
    'EXEC-06-N05': {
        'trigger': 'peer_hash_as_attestation',
        'facts': {'peer_hash_present': True,
                  'trusted_local_measurement_present': False,
                  'attestation_accepted': False, 'new_effects': 0,
                  'outcome': 'denied'}},
    'EXEC-08-N01': {
        'trigger': 'model_skips_diagnostic_verifier',
        'facts': {'diagnostic_verifier_called': False,
                  'internal_gate_called': True, 'trusted_verdict_present': False,
                  'new_effects': 0, 'outcome': 'denied'}},
    'EXEC-08-N02': {
        'trigger': 'model_requests_unrestricted_signing',
        'facts': {'model_signing_surface_present': False,
                  'signed_intents': 0, 'new_effects': 0,
                  'outcome': 'denied'}},
    'EXEC-08-N03': {
        'trigger': 'internal_gate_timeout',
        'facts': {'internal_gate_called': True, 'gate_timed_out': True,
                  'new_effects': 0, 'outcome': 'denied'}},
}


EVIDENCE_FIELDS = {
    'EXEC-04-N04': {'verified_bytes_equal_final_bytes'},
    'EXEC-05-N05': {'commit_observed', 'cancel_observed', 'claimed_rollback'},
    'EXEC-06-N04': {'measured_instance_equal_loaded_instance'},
    'EXEC-08-N03': {'internal_gate_called', 'gate_timed_out'},
}


def sample_evidence(case_id):
    """Inert controls for the independently computed host facts."""
    examples = {
        'EXEC-04-N04': {'verified_sha256': 'a' * 64,
                        'final_sha256': 'b' * 64},
        'EXEC-05-N05': {'commit_sequence': 1,
                        'cancel_sequence': 2, 'rollback_claimed': False},
        'EXEC-06-N04': {'measured_instance': 'measured-1',
                        'loader_target_instance': 'changed-2'},
        'EXEC-08-N03': {'gate_start_ms': 1000, 'deadline_ms': 1020,
                        'observed_ms': 1021, 'completion_ms': None},
    }
    return examples.get(case_id)


def derived_facts(case_id, evidence):
    if case_id == 'EXEC-04-N04':
        require(type(evidence) is dict and
                set(evidence) == {'verified_sha256', 'final_sha256'} and
                all(type(value) is str and len(value) == 64 and
                    all(char in '0123456789abcdef' for char in value)
                    for value in evidence.values()), 'exact verified/final byte hashes')
        return {'verified_bytes_equal_final_bytes':
                evidence['verified_sha256'] == evidence['final_sha256']}, True
    if case_id == 'EXEC-05-N05':
        require(type(evidence) is dict and
                set(evidence) == {'commit_sequence', 'cancel_sequence',
                                  'rollback_claimed'} and
                type(evidence['commit_sequence']) is int and
                type(evidence['cancel_sequence']) is int and
                type(evidence['rollback_claimed']) is bool and
                0 <= evidence['commit_sequence'] < 2**32 and
                0 <= evidence['cancel_sequence'] < 2**32,
                'ordered commit and cancel evidence')
        return {'commit_observed': True, 'cancel_observed': True,
                'claimed_rollback': evidence['rollback_claimed']}, \
            evidence['commit_sequence'] < evidence['cancel_sequence']
    if case_id == 'EXEC-06-N04':
        require(type(evidence) is dict and
                set(evidence) == {'measured_instance', 'loader_target_instance'} and
                all(type(value) is str and 1 <= len(value) <= 128
                    for value in evidence.values()), 'measured and loaded instance IDs')
        return {'measured_instance_equal_loaded_instance':
                evidence['measured_instance'] ==
                evidence['loader_target_instance']}, True
    if case_id == 'EXEC-08-N03':
        require(type(evidence) is dict and
                set(evidence) == {'gate_start_ms', 'deadline_ms',
                                  'observed_ms', 'completion_ms'} and
                all(type(evidence[key]) is int and 0 <= evidence[key] < 2**64
                    for key in ('gate_start_ms', 'deadline_ms', 'observed_ms')) and
                (evidence['completion_ms'] is None or
                 type(evidence['completion_ms']) is int and
                 0 <= evidence['completion_ms'] < 2**64),
                'trusted gate timing evidence')
        start = evidence['gate_start_ms']
        deadline = evidence['deadline_ms']
        observed = evidence['observed_ms']
        completed = evidence['completion_ms']
        ordered = start < deadline <= observed and \
            (completed is None or start <= completed <= observed)
        timed_out = completed is None or completed >= deadline
        return {'internal_gate_called': True,
                'gate_timed_out': timed_out}, ordered
    require(evidence is None, 'unexpected host evidence')
    return {}, True


def sample_observation(case_id):
    contract = CONTRACTS[case_id]
    expected = contract['facts']
    observation = {'case_id': case_id, 'trigger': contract['trigger'],
                   'facts': {key: value for key, value in expected.items()
                             if key not in EVIDENCE_FIELDS.get(case_id, ())},
                   'observer_effects': expected['new_effects'],
                   'subject_effects': expected['new_effects']}
    if case_id in EVIDENCE_FIELDS:
        observation['evidence'] = sample_evidence(case_id)
    return observation


def inspect(case_id, observation):
    """Derive a verdict from typed facts, never from a subject-reported PASS."""
    required_fields = {'case_id', 'trigger', 'facts',
                       'observer_effects', 'subject_effects'}
    if case_id in EVIDENCE_FIELDS:
        required_fields.add('evidence')
    require(case_id in CONTRACTS and type(observation) is dict and
            set(observation) == required_fields and
            observation['case_id'] == case_id and
            observation['trigger'] == CONTRACTS[case_id]['trigger'],
            'host observation identity')
    facts = observation['facts']
    expected = CONTRACTS[case_id]['facts']
    computed, evidence_ordered = derived_facts(case_id, observation.get('evidence'))
    require(type(facts) is dict and
            set(facts) == set(expected) - set(computed) and
            all(type(facts[key]) is type(value) for key, value in expected.items()
                if key in facts)
            and type(observation['observer_effects']) is int and
            type(observation['subject_effects']) is int and
            0 <= observation['observer_effects'] <= 1 and
            0 <= observation['subject_effects'] <= 1,
            'typed bounded host facts')
    all_facts = dict(facts, **computed)
    clean = (evidence_ordered and
             all(all_facts[key] == value for key, value in expected.items()) and
             observation['observer_effects'] == facts['new_effects'] and
             observation['subject_effects'] == facts['new_effects'])
    return {'verdict': 'ACCEPT' if clean else 'REJECT',
            'output': {'accepted': clean, 'observed_trigger':
                       observation['trigger']},
            'effects': {'protected': observation['observer_effects']}}
