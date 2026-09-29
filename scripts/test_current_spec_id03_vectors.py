"""Named-key cases preserve independent registry-vector provenance."""

import unittest

import check_current_spec_id03_vectors as checker


class ID03VectorTests(unittest.TestCase):
    def test_named_key_boundaries(self):
        self.assertEqual(checker.check(), 6)


if __name__ == '__main__':
    unittest.main()
