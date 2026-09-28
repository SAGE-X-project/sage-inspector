"""ID-02 fixtures distinguish registry authority from parser syntax."""

import unittest

import check_current_spec_id02_vectors as checker


class ID02VectorTests(unittest.TestCase):
    def test_authority_and_canonical_boundaries(self):
        self.assertEqual(checker.check(), 4)


if __name__ == '__main__':
    unittest.main()
