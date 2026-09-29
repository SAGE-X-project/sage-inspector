"""Inert host traces enforce case-specific denial and effect boundaries."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from check_current_spec_host_contracts import check
from current_spec_host_probe import CONTRACTS, inspect
from current_spec_host_trace_bridge import observe


class HostContractTests(unittest.TestCase):
    def test_pinned_host_cases_and_tracks(self):
        self.assertEqual(check(), 30)

    def test_each_case_rejects_every_changed_security_fact(self):
        for ident, contract in CONTRACTS.items():
            base = {'case_id': ident, 'trigger': contract['trigger'],
                    'facts': copy.deepcopy(contract['facts']),
                    'observer_effects': contract['facts']['new_effects'],
                    'subject_effects': contract['facts']['new_effects']}
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
        trace = {'case_id': ident, 'trigger': CONTRACTS[ident]['trigger'],
                 'facts': CONTRACTS[ident]['facts'].copy(),
                 'observer_effects': 1, 'subject_effects': 0}
        self.assertEqual(inspect(ident, trace)['verdict'], 'REJECT')

    def test_bridge_does_not_send_expected_answer_to_host(self):
        ident = 'EXEC-08-N03'
        payload = {'operation': 'sage.host.execution.trace',
                   'input': {'case_id': ident,
                             'trigger': CONTRACTS[ident]['trigger']}}
        request = {'schema_version': 1,
                   'spec_revision': '5bcf511e604579afa63f434013447f44b6858828',
                   'id': ident, 'track': 'runtime', 'input': payload}
        trace = {'case_id': ident, 'trigger': CONTRACTS[ident]['trigger'],
                 'facts': CONTRACTS[ident]['facts'].copy(),
                 'observer_effects': 0, 'subject_effects': 0}
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


if __name__ == '__main__':
    unittest.main()
