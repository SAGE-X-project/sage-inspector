"""MSG-06 failure fixtures preserve signed and unauthenticated boundaries."""

import unittest

import check_current_spec_msg06_vectors as checker


class MSG06VectorTests(unittest.TestCase):
    def test_four_failure_conditions(self):
        self.assertEqual(checker.check(), 4)


if __name__ == '__main__':
    unittest.main()
