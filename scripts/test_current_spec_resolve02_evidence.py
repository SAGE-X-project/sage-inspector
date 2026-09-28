"""Archived resolution evidence remains incomplete but reproducible."""

import unittest

import check_current_spec_resolve02_evidence as checker


class Resolve02EvidenceTests(unittest.TestCase):
    def test_resolution_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
