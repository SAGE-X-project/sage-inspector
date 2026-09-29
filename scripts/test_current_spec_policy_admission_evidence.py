"""Archived signed policy denials remain reproducible."""

import unittest

import check_current_spec_policy_admission_evidence as checker


class PolicyAdmissionEvidenceTests(unittest.TestCase):
    def test_both_cores(self):
        rows = checker.check()
        self.assertEqual(set(rows), {'go', 'rust'})
        self.assertTrue(all(row['PARTIAL'] == 2 for row in rows.values()))


if __name__ == '__main__':
    unittest.main()
