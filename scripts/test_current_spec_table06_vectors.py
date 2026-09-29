"""Transport header projections cannot substitute for verified body routing."""

import copy
import unittest

import check_current_spec_table06_vectors as checker


class Table06VectorTests(unittest.TestCase):
    def test_pinned_header_cases_and_controls(self):
        self.assertEqual(checker.check(), (3, 18))

    def test_matching_projection_still_cannot_be_routing_authority(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        self.assertEqual(checker.decision(good), 'ACCEPT')
        changed = copy.deepcopy(good)
        changed['routing']['source'] = 'header-projection'
        self.assertEqual(checker.decision(changed), 'REJECT')


if __name__ == '__main__':
    unittest.main()
