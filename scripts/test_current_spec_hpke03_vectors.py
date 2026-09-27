"""HPKE-03 fixtures retain the exact transcript and independent schedule."""

import unittest

import check_current_spec_hpke03_vectors as checker


class HPKE03VectorTests(unittest.TestCase):
    def test_five_transcript_and_combiner_conditions(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
