"""Registry values retain meaning and new assignments require review."""

import copy
import unittest

import check_current_spec_table01_vectors as checker


class Table01VectorTests(unittest.TestCase):
    def test_pinned_registry_cases_and_proposal_controls(self):
        self.assertEqual(checker.check(), (4, 2, 8))

    def test_obsolete_and_private_values_do_not_become_public(self):
        suite = checker.load((checker.ROOT / checker.SOURCE).read_bytes())
        good = suite['cases'][0]['input']
        reused = copy.deepcopy(good)
        reused['candidate_registry']['domain_labels'][1]['status'] = 'assigned'
        self.assertEqual(checker.decision(reused), 'REJECT')
        private = copy.deepcopy(good)
        private['observed_wire_algorithm'] = 'x-local-signature'
        self.assertEqual(checker.decision(private), 'REJECT')
        private['wire_scope'] = 'internal'
        self.assertEqual(checker.decision(private), 'ACCEPT')


if __name__ == '__main__':
    unittest.main()
