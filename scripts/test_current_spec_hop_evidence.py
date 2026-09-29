"""Archived bounded hop observations remain reproducible."""

import unittest

import check_current_spec_hop_evidence as checker


class HopEvidenceTests(unittest.TestCase):
    def test_both_cores(self):
        rows = checker.check()
        self.assertEqual(set(rows), {'go', 'rust'})
        self.assertTrue(all(row['PARTIAL'] == 3 for row in rows.values()))


if __name__ == '__main__':
    unittest.main()
