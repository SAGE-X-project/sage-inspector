"""Preserved MSG-01 evidence keeps partial and unsupported boundaries."""

import unittest

import check_current_spec_msg01_evidence as checker


class MSG01EvidenceTests(unittest.TestCase):
    def test_both_core_reports_reassess_to_recorded_status(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
