"""Archived metadata observations remain incomplete but reproducible."""

import unittest

import check_current_spec_resolve03_evidence as checker


class Resolve03EvidenceTests(unittest.TestCase):
    def test_metadata_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
