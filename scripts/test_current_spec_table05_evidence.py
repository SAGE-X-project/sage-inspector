"""Archived registry kind-selection observations remain reproducible."""

import unittest

import check_current_spec_table05_evidence as checker


class Table05EvidenceTests(unittest.TestCase):
    def test_registry_kind_selection_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
