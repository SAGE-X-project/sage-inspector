"""Safe catalog, verdict and CLI checks for host-port evidence controls."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from host_port_contract import ROOT, catalog, report


SPEC = Path(os.environ.get('SAGE_SPEC_ROOT', '../sage-spec')).resolve()


def observation(case):
    facts = {
        'host-capture-changed': {
            'submitted_bytes_sha256': 'a' * 64,
            'captured_bytes_sha256': 'b' * 64,
            'capture_before_model': True,
            'protected_store_identity': 'store-1'},
        'host-proposal-unchecked': {
            'proposal_digest': 'a' * 64,
            'approved_policy_digest': 'b' * 64,
            'authorization_event_ids': [], 'signed_intent_ids': []},
        'host-signing-key-missing': {
            'registry_source_identity': 'source-1', 'active_role_keys': [],
            'selected_signing_key': None, 'fallback_attempts': []},
        'host-component-reopened': {
            'approved_manifest_digest': 'a' * 64,
            'measured_instance_id': 'first', 'loaded_instance_id': 'second',
            'load_event_ids': []},
        'host-signing-oracle': {
            'model_callable_routes': ['propose'],
            'authorization_capability_ids': [], 'signer_event_ids': [],
            'signed_intent_ids': []},
        'host-uncertain-retry': {
            'original_envelope_sha256': 'a' * 64,
            'original_call_id': 'call-1', 'retry_call_ids': ['call-1'],
            'durable_journal_state': 'UNKNOWN'},
        'host-close-before-reserve': {
            'owner_close_sequence': 1, 'reservation_sequence': None,
            'queue_insertions': 0, 'durable_call_state': 'ABSENT'},
        'host-final-arguments-change': {
            'verified_arguments_sha256': 'a' * 64,
            'dispatch_arguments_sha256': 'b' * 64,
            'effect_event_ids': [], 'loaded_instance_id': 'instance-1'},
        'host-direct-route': {
            'complete_route_inventory': ['route-1'],
            'isolated_capabilities': ['network'], 'gate_event_ids': [],
            'independent_effect_event_ids': []},
        'host-required-hook-disabled': {
            'host_build': 'build-1', 'hook_configuration': 'disabled',
            'mandatory_gate_inventory': [],
            'protected_profile_advertisements': []},
        'host-gate-timeout': {
            'gate_start_time': 1, 'gate_deadline': 2,
            'gate_completion_time': None,
            'independent_effect_event_ids': []},
        'host-result-unverified': {
            'tracked_call_id': 'call-1', 'result_envelope_sha256': None,
            'verification_event_ids': [], 'output_release_event_ids': []},
        'host-optional-verifier-skipped': {
            'diagnostic_call_ids': [], 'mandatory_gate_event_ids': ['gate-1'],
            'trusted_verdict_event_ids': [], 'output_release_event_ids': []},
    }[case['id']]
    return {
        'id': case['id'],
        'subject_revision': 'a' * 40,
        'observer_revision': 'b' * 40,
        'observer_id': 'independent-local-observer',
        'independent_observer': True,
        'actual_state': case['expected_state'],
        'new_protected_effects': 0,
        'observations': facts,
    }


class HostPortContractTests(unittest.TestCase):
    def test_all_ports_link_to_frozen_cases(self):
        suite = catalog(SPEC)
        self.assertEqual(len(suite['cases']), 13)
        self.assertEqual(len({row['port'] for row in suite['cases']}), 9)
        self.assertEqual(report(suite)['counts'], {'NOT_RUN': 13})

    def test_wrong_case_link_and_missing_port_fail(self):
        suite = catalog()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'cases.json'
            changed = copy.deepcopy(suite)
            changed['cases'][0]['rule_id'] = 'EXEC-08'
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'source case'):
                catalog(suite_path=path)
            changed = copy.deepcopy(suite)
            changed['cases'][0]['port'] = 'EffectOwner'
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'nine host ports'):
                catalog(suite_path=path)

    def test_source_drift_fails(self):
        suite = catalog()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'cases.json'
            changed = copy.deepcopy(suite)
            changed['source_sha256']['verification/traceability.json'] = '0' * 64
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'normative source bytes'):
                catalog(suite_path=path)

    def test_bounded_observations_never_become_pass(self):
        suite = catalog()
        sample = observation(suite['cases'][0])
        result = report(suite, [sample])
        self.assertEqual(result['counts'], {'PARTIAL': 1, 'NOT_RUN': 12})
        sample['observations'] = {}
        self.assertEqual(report(suite, [sample])['counts'],
                         {'PARTIAL': 1, 'NOT_RUN': 12})
        sample['actual_state'] = 'unknown'
        self.assertEqual(report(suite, [sample])['counts'],
                         {'FAIL': 1, 'NOT_RUN': 12})

    def test_each_case_rejects_contradictory_facts(self):
        suite = catalog()
        for case in suite['cases']:
            with self.subTest(case=case['id']):
                sample = observation(case)
                self.assertEqual(report(suite, [sample])['counts'],
                                 {'PARTIAL': 1, 'NOT_RUN': 12})
                sample['observations'][case['required_observations'][0]] = False
                self.assertEqual(report(suite, [sample])['counts'],
                                 {'FAIL': 1, 'NOT_RUN': 12})
        sample['actual_state'] = suite['cases'][0]['expected_state']
        sample['new_protected_effects'] = 1
        self.assertEqual(report(suite, [sample])['counts'],
                         {'FAIL': 1, 'NOT_RUN': 12})

    def test_duplicate_or_unpinned_observation_fails(self):
        suite = catalog()
        sample = observation(suite['cases'][0])
        with self.assertRaisesRegex(ValueError, 'identity or bounds'):
            report(suite, [sample, sample])
        sample['subject_revision'] = 'unpinned'
        with self.assertRaisesRegex(ValueError, 'identity or bounds'):
            report(suite, [sample])

    def test_cli_no_subject_runtime(self):
        proc = subprocess.run(
            [sys.executable, '-B', str(ROOT / 'scripts/host_port_contract.py'),
             '--spec-root', str(SPEC)],
            cwd=ROOT, capture_output=True, text=True, timeout=15,
            check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['counts'], {'NOT_RUN': 13})

    def test_cli_bounded_observation_runtime(self):
        suite = catalog(SPEC)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'observation.json'
            path.write_text(json.dumps([observation(suite['cases'][0])]))
            proc = subprocess.run(
                [sys.executable, '-B', str(ROOT / 'scripts/host_port_contract.py'),
                 '--spec-root', str(SPEC), '--observations', str(path)],
                cwd=ROOT, capture_output=True, text=True, timeout=15,
                check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)['counts'],
                             {'PARTIAL': 1, 'NOT_RUN': 12})


if __name__ == '__main__':
    unittest.main()
