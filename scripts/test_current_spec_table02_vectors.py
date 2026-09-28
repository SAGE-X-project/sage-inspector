"""Signature suite selection respects exact names and declared key roles."""

import copy
import unittest

import check_current_spec_table02_vectors as checker


class Table02VectorTests(unittest.TestCase):
    def test_pinned_suite_cases_and_controls(self):
        self.assertEqual(checker.check(), (3, 12))

    def test_optional_suite_never_falls_back(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        disabled = copy.deepcopy(good)
        disabled['implementation_support']['sage-secp256k1-keccak256'] = False
        self.assertIsNone(checker.selected(disabled))
        kem = copy.deepcopy(good)
        kem['request']['alg'] = 'x25519'
        self.assertIsNone(checker.selected(kem))


if __name__ == '__main__':
    unittest.main()
