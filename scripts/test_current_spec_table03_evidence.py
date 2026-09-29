"""Archived registry key encoding observations remain reproducible."""

import unittest

import check_current_spec_table03_evidence as checker


class Table03EvidenceTests(unittest.TestCase):
    def test_registry_key_encoding_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
