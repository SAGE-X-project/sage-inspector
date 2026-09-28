"""Isolated record defects stay separate from live core verdicts."""

import unittest

import check_current_spec_reg01_vectors as checker


class Reg01VectorTests(unittest.TestCase):
    def test_record_shape_and_lifetime_key_cases(self):
        self.assertEqual(checker.check(), (5, 3))


if __name__ == '__main__':
    unittest.main()
