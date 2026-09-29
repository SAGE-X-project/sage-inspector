"""Pinned missing-ledger observations remain reproducible and partial."""

import unittest

import check_current_spec_exec_lost_ledger_evidence as checker


class LostLedgerEvidenceTests(unittest.TestCase):
    def test_go_and_rust_fail_closed(self):
        result = checker.check()
        self.assertEqual(result['go']['PARTIAL'], 2)
        self.assertEqual(result['rust']['PARTIAL'], 2)


if __name__ == '__main__':
    unittest.main()
