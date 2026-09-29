"""A signed card must remain bound to fresh registry state."""

import unittest

import check_current_spec_card03_vectors as checker


class Card03VectorTests(unittest.TestCase):
    def test_card_freshness_and_registry_state_boundaries(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
