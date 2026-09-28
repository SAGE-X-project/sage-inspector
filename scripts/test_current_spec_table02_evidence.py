"""Archived algorithm identifier observations remain reproducible."""

import unittest

import check_current_spec_table02_evidence as checker


class Table02EvidenceTests(unittest.TestCase):
    def test_signature_algorithm_identifier_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
