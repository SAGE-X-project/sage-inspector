"""Archived key dereference observations remain incomplete but reproducible."""

import unittest

import check_current_spec_resolve04_evidence as checker


class Resolve04EvidenceTests(unittest.TestCase):
    def test_key_dereference_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
