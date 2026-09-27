"""The preserved positive parser result cannot establish full conformance."""

import unittest

import check_current_spec_jcs_positive_evidence as checker


class PreservedJCSPositiveEvidenceTests(unittest.TestCase):
    def test_both_core_results_remain_partial(self):
        self.assertEqual(checker.check(), {'go': 'PARTIAL', 'rust': 'PARTIAL'})


if __name__ == '__main__':
    unittest.main()
