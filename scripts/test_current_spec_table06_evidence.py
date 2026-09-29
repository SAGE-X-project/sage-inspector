"""Archived transport header projection observations remain reproducible."""

import unittest

import check_current_spec_table06_evidence as checker


class Table06EvidenceTests(unittest.TestCase):
    def test_transport_header_projection_evidence(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
