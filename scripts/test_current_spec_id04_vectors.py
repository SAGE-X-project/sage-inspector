"""Lifecycle fixtures preserve authorization and identity invariants."""

import unittest

import check_current_spec_id04_vectors as checker


class ID04VectorTests(unittest.TestCase):
    def test_lifecycle_conditions(self):
        self.assertEqual(checker.check(), 4)


if __name__ == '__main__':
    unittest.main()
