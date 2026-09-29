"""HPKE-04 inner signatures must not imply complete response verification."""

import unittest

import check_current_spec_hpke04_evidence as checker


class HPKE04EvidenceTests(unittest.TestCase):
    def test_both_core_reports_reassess_to_recorded_status(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
