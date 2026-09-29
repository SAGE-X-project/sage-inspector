"""Keep PoP cryptography separate from Registry authorization."""

import unittest

import check_current_spec_reg04_vectors as checker


class Reg04VectorTests(unittest.TestCase):
    def test_pop_kem_and_controller_boundaries(self):
        self.assertEqual(checker.check(), (5, 4))


if __name__ == '__main__':
    unittest.main()
