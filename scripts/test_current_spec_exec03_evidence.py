"""Archived Go and Rust intent checks remain partial case evidence."""

import unittest

import check_current_spec_exec03_evidence as checker


class Exec03EvidenceTests(unittest.TestCase):
    def test_revision_bound_core_observations(self):
        result = checker.check()
        self.assertEqual(result['go']['PARTIAL'], 43)
        self.assertEqual(result['rust']['PARTIAL'], 50)


if __name__ == '__main__':
    unittest.main()
