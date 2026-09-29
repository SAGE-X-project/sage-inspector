"""Inert host traces enforce case-specific denial and effect boundaries."""

import copy
import json
from pathlib import Path
import stat
import tempfile
import unittest

from check_current_spec_host_contracts import check
from current_spec_host_probe import CONTRACTS, inspect, sample_observation
from current_spec_host_trace_bridge import observe


class HostContractTests(unittest.TestCase):
    def test_pinned_host_cases_and_tracks(self):
        self.assertEqual(check(), 30)

    def test_each_case_rejects_every_changed_security_fact(self):
        for ident, contract in CONTRACTS.items():
            base = sample_observation(ident)
            self.assertEqual(inspect(ident, base)['verdict'], 'ACCEPT')
            for key, value in base['facts'].items():
                with self.subTest(ident=ident, fact=key):
                    trace = copy.deepcopy(base)
                    trace['facts'][key] = (not value if type(value) is bool
                                           else (value + 1 if type(value) is int
                                                 else 'different'))
                    self.assertEqual(inspect(ident, trace)['verdict'], 'REJECT')
            for counter in ('observer_effects', 'subject_effects'):
                with self.subTest(ident=ident, counter=counter):
                    trace = copy.deepcopy(base)
                    trace[counter] = 1 - trace[counter]
                    self.assertEqual(inspect(ident, trace)['verdict'], 'REJECT')

    def test_external_effect_disagreement_is_not_accepted(self):
        ident = 'EXEC-08-N03'
        trace = sample_observation(ident)
        trace['observer_effects'] = 1
        self.assertEqual(inspect(ident, trace)['verdict'], 'REJECT')

    def test_computed_facts_reject_changed_bytes_order_and_deadline(self):
        cases = {
            'EXEC-01-P': ('plugin_accessible_capabilities', ['sign']),
            'EXEC-01-N01': ('granted_key_read_ids', ['read-1']),
            'EXEC-01-N02': ('verifier_digest_after', 'b' * 64),
            'EXEC-01-N03': ('unmediated_effect_ids', ['effect-1']),
            'EXEC-01-N04': ('profile_advertisements', ['protected']),
            'EXEC-02-N02': ('checked_proposal_ids', ['proposal-1']),
            'EXEC-04-N04': ('final_sha256', 'a' * 64),
            'EXEC-05-N05': ('cancel_sequence', 0),
            'EXEC-06-N01': ('baseline_digest_after', 'b' * 64),
            'EXEC-06-N02': ('loaded_artifact_ids', ['artifact-1']),
            'EXEC-06-N04': ('loader_target_instance', 'measured-1'),
            'EXEC-06-N05': ('local_measurement_ids', ['measure-1']),
            'EXEC-08-N01': ('gate_call_ids', []),
            'EXEC-08-N02': ('model_callable_operations', ['sign']),
            'EXEC-08-N03': ('completion_ms', 1019),
        }
        for ident, (field, value) in cases.items():
            with self.subTest(ident=ident):
                trace = sample_observation(ident)
                self.assertEqual(inspect(ident, trace)['verdict'], 'ACCEPT')
                trace['evidence'][field] = value
                self.assertEqual(inspect(ident, trace)['verdict'], 'REJECT')

    def test_computed_facts_cannot_be_supplied_by_subject(self):
        for ident, field in {
                'EXEC-01-P': 'capability_isolated',
                'EXEC-01-N01': 'key_read_succeeded',
                'EXEC-01-N02': 'verifier_replaced',
                'EXEC-01-N03': 'unmediated_effects',
                'EXEC-01-N04': 'hook_disabled',
                'EXEC-02-N02': 'proposal_checked',
                'EXEC-04-N04': 'verified_bytes_equal_final_bytes',
                'EXEC-05-N05': 'claimed_rollback',
                'EXEC-06-N01': 'baseline_changed',
                'EXEC-06-N02': 'artifact_is_symlink',
                'EXEC-06-N04': 'measured_instance_equal_loaded_instance',
                'EXEC-06-N05': 'peer_hash_present',
                'EXEC-08-N01': 'internal_gate_called',
                'EXEC-08-N02': 'model_signing_surface_present',
                'EXEC-08-N03': 'gate_timed_out'}.items():
            with self.subTest(ident=ident):
                trace = sample_observation(ident)
                trace['facts'][field] = CONTRACTS[ident]['facts'][field]
                with self.assertRaises(ValueError):
                    inspect(ident, trace)

    def test_evidence_must_be_bounded_and_well_typed(self):
        cases = {
            'EXEC-01-P': ('gate_call_ids', ['gate-1'] * 2),
            'EXEC-01-N01': ('granted_key_read_ids', ['']),
            'EXEC-01-N02': ('verifier_digest_before', 'bad'),
            'EXEC-01-N03': ('unmediated_effect_ids', ['effect-1'] * 2),
            'EXEC-01-N04': ('hook_state', 'unknown'),
            'EXEC-02-N02': ('checked_proposal_ids', ['proposal-1'] * 2),
            'EXEC-04-N04': ('verified_sha256', 'not-a-digest'),
            'EXEC-05-N05': ('commit_sequence', True),
            'EXEC-06-N01': ('baseline_digest_after', 'bad'),
            'EXEC-06-N02': ('artifact_lstat_mode', -1),
            'EXEC-06-N04': ('measured_instance', ''),
            'EXEC-06-N05': ('peer_hash', 'bad'),
            'EXEC-08-N01': ('gate_call_ids', ['gate-1'] * 2),
            'EXEC-08-N02': ('model_callable_operations', ['sign'] * 2),
            'EXEC-08-N03': ('deadline_ms', '1020'),
        }
        for ident, (field, value) in cases.items():
            with self.subTest(ident=ident):
                trace = sample_observation(ident)
                trace['evidence'][field] = value
                with self.assertRaises(ValueError):
                    inspect(ident, trace)
        trace = sample_observation('EXEC-06-N02')
        trace['evidence']['artifact_lstat_mode'] = stat.S_IFREG | 0o644
        self.assertEqual(inspect('EXEC-06-N02', trace)['verdict'], 'REJECT')

    def test_bridge_does_not_send_expected_answer_to_host(self):
        ident = 'EXEC-08-N03'
        payload = {'operation': 'sage.host.execution.trace',
                   'input': {'case_id': ident,
                             'trigger': CONTRACTS[ident]['trigger']}}
        request = {'schema_version': 1,
                   'spec_revision': '5bcf511e604579afa63f434013447f44b6858828',
                   'id': ident, 'track': 'runtime', 'input': payload}
        trace = sample_observation(ident)
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'host-observer'
            adapter.write_text('#!/usr/bin/env python3\n'
                               'import json,sys\n'
                               'received=json.load(sys.stdin)\n'
                               'assert set(received)=={"case_id","trigger"}\n'
                               f'print({json.dumps(json.dumps(trace))})\n')
            adapter.chmod(0o700)
            result = observe(json.dumps(request).encode(), adapter)
        self.assertEqual(result['actual']['verdict'], 'ACCEPT')

    def test_bridge_derives_all_host_boundaries_from_subprocess_evidence(self):
        revision = '5bcf511e604579afa63f434013447f44b6858828'
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'host-observer'
            for ident in CONTRACTS:
                with self.subTest(ident=ident):
                    trace = sample_observation(ident)
                    adapter.write_text('#!/usr/bin/env python3\n'
                                       'import json,sys\n'
                                       'received=json.load(sys.stdin)\n'
                                       "assert set(received)=={'case_id','trigger'}\n"
                                       f'print({json.dumps(json.dumps(trace))})\n')
                    adapter.chmod(0o700)
                    request = {'schema_version': 1, 'spec_revision': revision,
                               'id': ident, 'track': 'runtime',
                               'input': {'operation': 'sage.host.execution.trace',
                                         'input': {'case_id': ident,
                                                   'trigger': CONTRACTS[ident]['trigger']}}}
                    self.assertEqual(observe(json.dumps(request).encode(), adapter)
                                     ['actual']['verdict'], 'ACCEPT')


if __name__ == '__main__':
    unittest.main()
