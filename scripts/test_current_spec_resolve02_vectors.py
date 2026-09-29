"""Resolution vectors require a current authenticated registry observation."""

import copy
import unittest

import check_current_spec_resolve02_vectors as checker


class Resolve02VectorTests(unittest.TestCase):
    def test_pinned_resolution_cases_and_controls(self):
        self.assertEqual(checker.check(), (6, 6))

    def test_version_rollback_and_missing_proof_fail_closed(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        rollback = copy.deepcopy(good)
        rollback['local_version_floor'] = 2
        self.assertEqual(checker.decision(rollback), 'REJECT')
        missing_proof = copy.deepcopy(good)
        del missing_proof['response']['body']['record']['keys'][0]['proof']
        missing_proof['response']['body_bytes'] = len(checker.json.dumps(
            missing_proof['response']['body'], separators=(',', ':')).encode())
        self.assertEqual(checker.decision(missing_proof), 'REJECT')


if __name__ == '__main__':
    unittest.main()
