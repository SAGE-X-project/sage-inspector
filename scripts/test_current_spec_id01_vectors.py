"""ID-01 invalid candidates require a valid DID control."""

import unittest

import check_current_spec_id01_vectors as checker


class ID01VectorTests(unittest.TestCase):
    def test_did_and_key_url_grammar_boundaries(self):
        self.assertEqual(checker.check(), 6)


if __name__ == '__main__':
    unittest.main()
