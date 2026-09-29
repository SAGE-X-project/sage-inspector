"""DID key lookup uses one exact accepted key from a current record."""

import copy
import unittest

import check_current_spec_resolve04_vectors as checker


class Resolve04VectorTests(unittest.TestCase):
    def test_pinned_dereference_cases_and_controls(self):
        self.assertEqual(checker.check(), (6, 6))

    def test_unknown_fragment_does_not_search_other_keys(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        changed = copy.deepcopy(good)
        changed['key_url'] = good['expected_peer'] + '#missing'
        self.assertEqual(checker.classify(changed), 'key.not-in-record')
        changed['key_url'] = good['expected_peer'] + '#signing-1'
        self.assertEqual(checker.classify(changed), 'key.wrong-relationship')


if __name__ == '__main__':
    unittest.main()
