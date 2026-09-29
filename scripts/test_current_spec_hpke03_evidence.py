"""Preserve actual HPKE-03 mismatches without claiming complete handshake proof."""

import unittest

import check_current_spec_hpke03_evidence as checker


class HPKE03EvidenceTests(unittest.TestCase):
    def test_both_core_reports_reassess_to_recorded_status(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
