"""Check bounded MSG-01 fixtures with an independent signature implementation."""

import unittest

import check_current_spec_msg01_vectors as checker


class MSG01VectorTests(unittest.TestCase):
    def test_signed_control_and_four_exact_mutations(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
