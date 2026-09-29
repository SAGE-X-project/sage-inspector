"""Signed hop fixtures remain pinned to exact independent decisions."""

import unittest

import check_current_spec_hop_vectors as checker


class HopVectorTests(unittest.TestCase):
    def test_parent_child_authorization_are_independent(self):
        self.assertEqual(checker.check(), 3)


if __name__ == '__main__':
    unittest.main()
