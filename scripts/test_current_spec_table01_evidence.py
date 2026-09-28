"""Archived registry governance observations remain incomplete but reproducible."""

import unittest

import check_current_spec_table01_evidence as checker


class Table01EvidenceTests(unittest.TestCase):
    def test_registry_governance_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
