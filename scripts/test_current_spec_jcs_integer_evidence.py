"""Cumulative signed JCS evidence remains bounded and incomplete."""

import unittest

import check_current_spec_jcs_integer_evidence as checker


class PreservedJCSIntegerEvidenceTests(unittest.TestCase):
    def test_go_and_rust_counts_are_rechecked(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
