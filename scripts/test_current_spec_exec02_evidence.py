"""Archived Go and Rust commitments remain partial case evidence."""

import unittest

import check_current_spec_exec02_evidence as checker


class Exec02EvidenceTests(unittest.TestCase):
    def test_revision_bound_core_observations(self):
        result = checker.check()
        self.assertEqual(result['go']['PARTIAL'], 37)
        self.assertEqual(result['rust']['PARTIAL'], 44)


if __name__ == '__main__':
    unittest.main()
