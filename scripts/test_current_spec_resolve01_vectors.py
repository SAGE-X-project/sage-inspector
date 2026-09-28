"""DID projection vectors preserve exact registry-derived relationships."""

import copy
import unittest

import check_current_spec_resolve01_vectors as checker


class Resolve01VectorTests(unittest.TestCase):
    def test_pinned_projection_and_mutations(self):
        self.assertEqual(checker.check(), (4, 6))

    def test_record_key_is_required_for_each_method(self):
        row = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]
        record, document = row['input']['record'], row['input']['candidate']
        changed = copy.deepcopy(document)
        changed['verificationMethod'][1]['publicKeyJwk']['x'] = (
            changed['verificationMethod'][0]['publicKeyJwk']['x'])
        self.assertEqual(checker.decision(record, changed), 'REJECT')


if __name__ == '__main__':
    unittest.main()
