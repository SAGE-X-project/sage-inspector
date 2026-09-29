"""Unsupported mutation APIs cannot certify registry lifecycle behavior."""

import unittest

import check_current_spec_id04_evidence as checker


class ID04EvidenceTests(unittest.TestCase):
    def test_both_cores_report_missing_mutation_boundary(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][3])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][3])


if __name__ == '__main__':
    unittest.main()
