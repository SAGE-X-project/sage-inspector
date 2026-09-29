"""Archived domain-label observations remain reproducible."""

import unittest

import check_current_spec_table04_evidence as checker


class Table04EvidenceTests(unittest.TestCase):
    def test_domain_separation_label_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
