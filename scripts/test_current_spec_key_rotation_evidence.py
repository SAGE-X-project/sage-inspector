"""Archived local key-withdrawal replay observations remain reproducible."""

import unittest

import check_current_spec_key_rotation_evidence as checker


class KeyRotationEvidenceTests(unittest.TestCase):
    def test_both_cores(self):
        rows = checker.check()
        self.assertEqual(set(rows), {'go', 'rust'})
        self.assertTrue(all(row['PARTIAL'] == 1 for row in rows.values()))


if __name__ == '__main__':
    unittest.main()
