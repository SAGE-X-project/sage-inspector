"""Preserved JCS observations must remain bounded and unpromoted."""

import unittest

import check_current_spec_jcs_evidence as checker


class PreservedJCSEvidenceTests(unittest.TestCase):
    def test_go_failure_and_rust_partial_result(self):
        self.assertEqual(checker.check(), {'go': 'FAIL', 'rust': 'PARTIAL'})


if __name__ == '__main__':
    unittest.main()
