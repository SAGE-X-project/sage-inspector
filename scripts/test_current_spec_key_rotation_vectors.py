"""Local replay fixture retains exact envelope and changed key authority."""

import unittest

import check_current_spec_key_rotation_vectors as checker


class KeyRotationVectorTests(unittest.TestCase):
    def test_exact_replay_after_key_withdrawal(self):
        self.assertEqual(checker.check(), 1)


if __name__ == '__main__':
    unittest.main()
