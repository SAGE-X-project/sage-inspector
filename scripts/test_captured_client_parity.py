"""Guard the independent signed Client observations and scope boundary."""

import copy
import json
import unittest

from inspect_captured_client_parity import ROOT, check_report, signed_fixture


class CapturedClientParityTests(unittest.TestCase):
    def report(self):
        return json.loads((ROOT / 'docs/evidence/captured-client-parity.json').read_text())

    def test_signed_fixture_uses_independent_original_bytes(self):
        config, _, original, _, _ = signed_fixture()
        envelope = json.loads(bytes.fromhex(config['envelope_hex']))
        self.assertEqual(original['request_id'], envelope['intent']['request_id'])
        self.assertEqual(original['expected'].removeprefix('ACCEPT:'),
                         envelope['intent']['original_digest'])

    def test_report_has_exact_journal_and_scope(self):
        self.assertEqual(check_report(self.report()), 12)
        for field, value in (('deployed_host', 'PASS'),
                             ('full_protocol_conformance', 'PASS')):
            changed = copy.deepcopy(self.report())
            changed[field] = value
            with self.assertRaisesRegex(ValueError, 'scope or provenance'):
                check_report(changed)

    def test_rejected_capture_cannot_gain_a_journal(self):
        changed = self.report()
        changed['cases'][0]['journal'] = 'CREATED'
        with self.assertRaisesRegex(ValueError, 'case verdicts or journal bytes'):
            check_report(changed)

    def test_cross_language_restart_cannot_change_journal(self):
        changed = self.report()
        changed['cases'][-1]['journal_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'case verdicts or journal bytes'):
            check_report(changed)


if __name__ == '__main__':
    unittest.main()
