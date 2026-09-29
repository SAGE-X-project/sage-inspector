"""Registry kind selection keeps reserved and unknown profiles closed."""

import copy
import unittest

import check_current_spec_table05_vectors as checker


class Table05VectorTests(unittest.TestCase):
    def test_pinned_kind_cases_and_controls(self):
        self.assertEqual(checker.check(), (3, 13))

    def test_reserved_kind_cannot_reuse_an_eip155_binding(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        self.assertEqual(checker.selected(good), 'eip155')
        reserved = copy.deepcopy(good)
        reserved['kind'] = 'solana'
        self.assertIsNone(checker.selected(reserved))


if __name__ == '__main__':
    unittest.main()
