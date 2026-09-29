"""Signed nonce changes and altered proof bytes never add a second effect."""

import unittest

import check_current_spec_exec05_replay_vectors as checker


class Exec05ReplayTests(unittest.TestCase):
    def test_pinned_replay_cases(self):
        self.assertEqual(checker.check(), 4)

    def test_all_sequences_allow_at_most_one_inert_dispatch(self):
        suite = checker.load((checker.ROOT / checker.SOURCE).read_bytes())
        self.assertTrue(all(row['expected']['effects']['dispatch'] == 1
                            for row in suite['cases']))


if __name__ == '__main__':
    unittest.main()
