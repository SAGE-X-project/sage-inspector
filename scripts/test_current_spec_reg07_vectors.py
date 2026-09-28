"""The reserved Solana kind has an exact error boundary."""

import unittest

import check_current_spec_reg07_vectors as checker


class Reg07VectorTests(unittest.TestCase):
    def test_reserved_kind_and_controls(self):
        self.assertEqual(checker.check(), (2, 3))


if __name__ == '__main__':
    unittest.main()
