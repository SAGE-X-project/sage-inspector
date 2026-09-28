"""Archived Registry selection evidence stays tied to its actual subject."""

import unittest

import check_current_spec_reg02_evidence as checker


class Reg02EvidenceTests(unittest.TestCase):
    def test_registry_selection_observations(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
