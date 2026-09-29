"""Archived lifecycle evidence stays tied to the exact core and runner."""

import unittest

import check_current_spec_reg03_evidence as checker


class Reg03EvidenceTests(unittest.TestCase):
    def test_lifecycle_observations(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
