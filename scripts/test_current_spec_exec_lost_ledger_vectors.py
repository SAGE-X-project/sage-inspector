"""Ledger loss is a no-new-dispatch case for both traceability rules."""

import unittest

import check_current_spec_exec_lost_ledger_vectors as checker


class LostLedgerVectorTests(unittest.TestCase):
    def test_pinned_lost_ledger_cases(self):
        self.assertEqual(checker.check(), 2)


if __name__ == '__main__':
    unittest.main()
