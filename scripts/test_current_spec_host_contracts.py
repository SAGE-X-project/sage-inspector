"""Inert host traces enforce case-specific denial and effect boundaries."""

import copy
import json
from pathlib import Path
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
            'EXEC-04-N04': ('final_sha256', 'a' * 64),
            'EXEC-05-N05': ('cancel_sequence', 0),
            'EXEC-06-N04': ('loader_target_instance', 'measured-1'),
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
                'EXEC-04-N04': 'verified_bytes_equal_final_bytes',
                'EXEC-05-N05': 'claimed_rollback',
                'EXEC-06-N04': 'measured_instance_equal_loaded_instance',
                'EXEC-08-N03': 'gate_timed_out'}.items():
            with self.subTest(ident=ident):
                trace = sample_observation(ident)
                trace['facts'][field] = CONTRACTS[ident]['facts'][field]
                with self.assertRaises(ValueError):
                    inspect(ident, trace)

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

    def test_bridge_derives_four_boundaries_from_subprocess_evidence(self):
        revision = '5bcf511e604579afa63f434013447f44b6858828'
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'host-observer'
            for ident in ('EXEC-04-N04', 'EXEC-05-N05',
                          'EXEC-06-N04', 'EXEC-08-N03'):
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
