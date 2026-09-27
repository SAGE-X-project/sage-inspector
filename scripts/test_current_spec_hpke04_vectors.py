"""HPKE-04 fixtures retain exact echo, ACK, and inner signature domains."""

import unittest

import check_current_spec_hpke04_vectors as checker


class HPKE04VectorTests(unittest.TestCase):
    def test_five_completion_conditions(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
