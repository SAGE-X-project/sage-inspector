"""HPKE-05 fixtures retain the record and provisional-state boundaries."""

import unittest

import check_current_spec_hpke05_vectors as checker


class HPKE05VectorTests(unittest.TestCase):
    def test_five_provisional_state_conditions(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
