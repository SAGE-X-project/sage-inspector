"""Resolution metadata cannot turn inspection success into authorization."""

import copy
import unittest

import check_current_spec_resolve03_vectors as checker


class Resolve03VectorTests(unittest.TestCase):
    def test_pinned_metadata_and_authorization_cases(self):
        self.assertEqual(checker.check(), (4, 8))

    def test_inactive_resolution_does_not_authorize(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        for index in (1, 2):
            changed = copy.deepcopy(good)
            changed['candidate']['protected_operation_gate'][index] = 'ALLOW'
            self.assertEqual(checker.decision(changed), 'REJECT')


if __name__ == '__main__':
    unittest.main()
