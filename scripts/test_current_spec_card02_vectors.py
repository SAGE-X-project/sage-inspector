"""The valid and wrong-domain card signatures remain distinguishable."""

import unittest

import check_current_spec_card02_vectors as checker


class Card02VectorTests(unittest.TestCase):
    def test_proof_and_domain_boundaries(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
