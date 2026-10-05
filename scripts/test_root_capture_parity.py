"""Guard the independent constructor vectors and bounded parity report."""

import copy
import json
import unittest

from inspect_root_capture_parity import ROOT, check_report, vectors


class RootCaptureParityTests(unittest.TestCase):
    def report(self):
        return json.loads((ROOT / 'docs/evidence/root-capture-parity.json').read_text())

    def test_vectors_have_independent_expected_bytes(self):
        suite, _ = vectors()
        self.assertEqual(len(suite['cases']), 7)
        self.assertNotEqual(suite['cases'][1]['expected'], suite['cases'][2]['expected'])

    def test_report_cannot_promote_host_or_client(self):
        report = self.report()
        self.assertEqual(check_report(report), 7)
        for field in ('deployed_host', 'protected_client'):
            changed = copy.deepcopy(report)
            changed[field] = 'PASS'
            with self.assertRaisesRegex(ValueError, 'scope or provenance'):
                check_report(changed)

    def test_cross_language_disagreement_is_rejected(self):
        report = self.report()
        report['cases'][0]['rust'] = 'REJECT'
        with self.assertRaisesRegex(ValueError, 'observations differ'):
            check_report(report)

    def test_source_revision_cannot_change(self):
        report = self.report()
        report['go_revision'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'scope or provenance'):
            check_report(report)


if __name__ == '__main__':
    unittest.main()
