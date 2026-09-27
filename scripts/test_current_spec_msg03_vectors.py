"""MSG-03 response vectors bind a retained request and expected peer."""

import unittest

import check_current_spec_msg03_vectors as checker


class MSG03VectorTests(unittest.TestCase):
    def test_signed_response_and_four_conditions(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
