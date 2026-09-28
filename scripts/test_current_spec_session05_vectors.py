"""SESSION-05 cases retain independent replay scenario relations."""

import unittest

import check_current_spec_session05_vectors as checker


class Session05VectorTests(unittest.TestCase):
    def test_reorder_concurrent_duplicate_bad_tag_replay_and_cap(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
