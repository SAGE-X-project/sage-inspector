"""Archived DID projection evidence remains incomplete but reproducible."""

import unittest

import check_current_spec_resolve01_evidence as checker


class Resolve01EvidenceTests(unittest.TestCase):
    def test_projection_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
