"""Signed result snapshots stay distinct from client consumption evidence."""

import unittest

import check_current_spec_exec_result_state_vectors as checker


class ExecutionResultStateVectorTests(unittest.TestCase):
    def test_pinned_pending_and_terminal_cases(self):
        self.assertEqual(checker.check(), 3)

    def test_late_reply_cannot_publish_expired_result(self):
        suite = checker.load((checker.ROOT / checker.SOURCE).read_bytes())
        expected = suite['cases'][2]['expected']
        self.assertEqual(expected['verdict'], 'REJECT')
        self.assertEqual(expected['output']['stored_result_status'], 'completed')
        self.assertFalse(expected['output']['published_terminal_matches_storage'])


if __name__ == '__main__':
    unittest.main()
