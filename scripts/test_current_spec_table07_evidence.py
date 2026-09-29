"""Archived diagnostic disclosure observations remain reproducible."""

import unittest

import check_current_spec_table07_evidence as checker


class Table07EvidenceTests(unittest.TestCase):
    def test_diagnostic_disclosure_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
