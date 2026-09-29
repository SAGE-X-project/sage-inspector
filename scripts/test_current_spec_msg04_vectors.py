"""MSG-04 vectors retain exact boundary sizes and one named condition."""

import unittest

import check_current_spec_msg04_vectors as checker


class MSG04VectorTests(unittest.TestCase):
    def test_signed_control_and_five_boundary_conditions(self):
        self.assertEqual(checker.check(), 6)


if __name__ == '__main__':
    unittest.main()
