"""Archived HTTP resolution observations remain incomplete but reproducible."""

import unittest

import check_current_spec_resolve05_evidence as checker


class Resolve05EvidenceTests(unittest.TestCase):
    def test_http_resolution_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
