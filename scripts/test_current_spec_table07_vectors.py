"""Application diagnostics remain local while failures stay generic."""

import copy
import unittest

import check_current_spec_table07_vectors as checker


class Table07VectorTests(unittest.TestCase):
    def test_pinned_diagnostic_cases_and_controls(self):
        self.assertEqual(checker.check(), (3, 30, 12))

    def test_distinct_local_codes_have_one_public_response(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        replay = copy.deepcopy(good)
        replay['diagnostic_code'] = 'sig.replay'
        replay['local_log']['code'] = 'sig.replay'
        self.assertEqual(checker.decision(good), 'ACCEPT')
        self.assertEqual(checker.decision(replay), 'ACCEPT')
        self.assertEqual(good['public_response'], replay['public_response'])


if __name__ == '__main__':
    unittest.main()
