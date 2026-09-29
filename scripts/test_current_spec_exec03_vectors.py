"""Intent examples keep signatures and independent schema defects distinct."""

import unittest

import check_current_spec_exec03_vectors as checker


class Exec03VectorTests(unittest.TestCase):
    def test_pinned_signed_intent_cases(self):
        self.assertEqual(checker.check(), 6)

    def test_unknown_field_has_valid_signature(self):
        suite = checker.load((checker.ROOT / checker.SOURCE).read_bytes())
        self.assertTrue(checker.signature_valid(suite['cases'][2]['input']))
        self.assertFalse(checker.signature_valid(suite['cases'][1]['input']))


if __name__ == '__main__':
    unittest.main()
