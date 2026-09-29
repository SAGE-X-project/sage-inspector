"""HPKE-02 cases retain exact domains and one changed trust condition."""

import unittest

import check_current_spec_hpke02_vectors as checker


class HPKE02VectorTests(unittest.TestCase):
    def test_five_binding_conditions(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
