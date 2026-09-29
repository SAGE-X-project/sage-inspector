"""Signed integer controls isolate one schema boundary per candidate."""

import copy
import unittest

import check_current_spec_jcs_integer_vectors as checker
from current_spec_catalog import load


class JCSIntegerVectorTests(unittest.TestCase):
    def test_all_pairs_have_valid_independent_signatures(self):
        self.assertEqual(checker.check(), 5)

    def test_modified_signed_integer_is_rejected_by_signature_check(self):
        fixture = load((checker.ROOT / 'vectors/0.10.0/current-spec/JCS-02-N01.json').read_bytes())
        inp = fixture['input']['input']['candidate']
        envelope = load(bytes.fromhex(inp['envelope_hex']))
        mutated = copy.deepcopy(envelope)
        mutated['intent']['created'] = 1700000000
        with self.assertRaisesRegex(ValueError, 'invalid signed Guard integer fixture'):
            checker.verify_signature(inp, mutated)


if __name__ == '__main__':
    unittest.main()
