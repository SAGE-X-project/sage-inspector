"""MSG-05 fixtures preserve exact timing and replay preconditions."""

import unittest

import check_current_spec_msg05_vectors as checker


class MSG05VectorTests(unittest.TestCase):
    def test_six_scoped_conditions(self):
        self.assertEqual(checker.check(), 6)


if __name__ == '__main__':
    unittest.main()
