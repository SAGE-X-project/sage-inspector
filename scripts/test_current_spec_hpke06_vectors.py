"""HPKE-06 fixtures retain exact boundary and independent source relations."""

import unittest

import check_current_spec_hpke06_vectors as checker


class HPKE06VectorTests(unittest.TestCase):
    def test_boundaries_and_admission_expectations(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
