"""Card size and schema cases retain a valid signed control."""

import unittest

import check_current_spec_card01_vectors as checker


class Card01VectorTests(unittest.TestCase):
    def test_card_schema_and_byte_boundaries(self):
        self.assertEqual(checker.check(), 6)


if __name__ == '__main__':
    unittest.main()
