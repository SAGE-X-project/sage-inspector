"""Pending and UNKNOWN stay distinct in current-spec fixtures."""

import unittest

import check_current_spec_exec_pending_vectors as checker


class PendingVectorTests(unittest.TestCase):
    def test_pinned_client_and_mcp_cases(self):
        self.assertEqual(checker.check(), 2)


if __name__ == '__main__':
    unittest.main()
