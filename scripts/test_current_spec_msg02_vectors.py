"""MSG-02 fixtures have a signed control and isolated receiver conditions."""

import unittest

import check_current_spec_msg02_vectors as checker


class MSG02VectorTests(unittest.TestCase):
    def test_signed_control_and_five_conditions(self):
        self.assertEqual(checker.check(), 6)


if __name__ == '__main__':
    unittest.main()
