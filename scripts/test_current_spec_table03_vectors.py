"""Registry key encodings bind exact record and JWK bytes."""

import copy
import unittest

import check_current_spec_table03_vectors as checker


class Table03VectorTests(unittest.TestCase):
    def test_pinned_key_cases_and_controls(self):
        self.assertEqual(checker.check(), (5, 11))

    def test_kem_key_cannot_be_used_for_signing(self):
        kem = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][3]['input']
        self.assertEqual(checker.key_type(kem), 'X25519')
        signing = copy.deepcopy(kem)
        signing['usage'] = 'signing'
        self.assertIsNone(checker.key_type(signing))


if __name__ == '__main__':
    unittest.main()
