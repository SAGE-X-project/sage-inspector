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


def inspect(case_id, observation):
    """Derive a verdict from typed facts, never from a subject-reported PASS."""
    require(case_id in CONTRACTS and type(observation) is dict and
            set(observation) == {'case_id', 'trigger', 'facts',
                                 'observer_effects', 'subject_effects'} and
            observation['case_id'] == case_id and
            observation['trigger'] == CONTRACTS[case_id]['trigger'],
            'host observation identity')
    facts = observation['facts']
    expected = CONTRACTS[case_id]['facts']
    require(type(facts) is dict and set(facts) == set(expected) and
            all(type(facts[key]) is type(value) for key, value in expected.items())
            and type(observation['observer_effects']) is int and
            type(observation['subject_effects']) is int and
            0 <= observation['observer_effects'] <= 1 and
            0 <= observation['subject_effects'] <= 1,
            'typed bounded host facts')
    clean = (all(facts[key] == value for key, value in expected.items()) and
             observation['observer_effects'] == facts['new_effects'] and
             observation['subject_effects'] == facts['new_effects'])
    return {'verdict': 'ACCEPT' if clean else 'REJECT',
            'output': {'accepted': clean, 'observed_trigger':
                       observation['trigger']},
            'effects': {'protected': observation['observer_effects']}}
