"""REG-06 deployment and claim controls remain distinct from live proof."""

import copy
import unittest

import check_current_spec_reg06_vectors as checker


class Reg06VectorTests(unittest.TestCase):
    def test_pinned_cases_and_claim(self):
        self.assertEqual(checker.check()[:2], (5, 2))

    def test_missing_deployment_obligation_fails_closed(self):
        base = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        for field in checker.FIELDS:
            changed = copy.deepcopy(base)
            del changed['candidate'][field]
            self.assertEqual(checker.decision(changed), 'REJECT', field)
        changed = copy.deepcopy(base)
        changed['observation']['finalized'] = False
        self.assertEqual(checker.decision(changed), 'REJECT')


if __name__ == '__main__':
    unittest.main()
