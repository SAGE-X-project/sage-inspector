"""Check that local outage evidence cannot be labeled as key revocation."""

import copy
import json
import unittest

from observe_live_web_message010 import ROOT, selected_cases


class LiveWebCaseSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT / 'vectors/0.10.0/live-web-message010.json').read_text())

    def test_each_direction_has_distinct_failure_cases(self):
        for sender in ('go', 'rust'):
            for receiver in ('go', 'rust'):
                self.assertEqual(selected_cases(self.fixture, 'key-revocation', sender, receiver),
                                 ('before-key-revocation', 'after-named-key-revocation'))
                self.assertEqual(selected_cases(self.fixture, 'registry-unavailable', sender, receiver),
                                 ('before-registry-unavailable', 'after-registry-unavailable'))
                self.assertEqual(selected_cases(self.fixture, 'registry-recovery', sender, receiver),
                                 ('before-registry-recovery-outage',
                                  'after-registry-recovery-outage',
                                  'closed-session-after-source-restart',
                                  'fresh-session-after-source-restart'))

    def test_rejects_case_or_conformance_promotion(self):
        for change in (
            lambda fixture: fixture['cases'][3].update(expected='ACCEPT'),
            lambda fixture: fixture.update(conformance='PASS'),
            lambda fixture: fixture['directions'].remove('rust-to-go'),
            lambda fixture: fixture['cases'][7].update(expected='REJECT'),
        ):
            fixture = copy.deepcopy(self.fixture)
            change(fixture)
            with self.assertRaises(AssertionError):
                selected_cases(fixture, 'registry-unavailable', 'rust', 'go')

    def test_rejects_unknown_failure_mode(self):
        with self.assertRaises(KeyError):
            selected_cases(self.fixture, 'unrecognized', 'go', 'go')


if __name__ == '__main__':
    unittest.main()
