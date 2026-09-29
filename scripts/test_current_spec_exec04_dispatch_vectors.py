"""Durable dispatch fixtures pin effects to the exact signed arguments."""

import unittest

import check_current_spec_exec04_dispatch_vectors as checker


class Exec04DispatchTests(unittest.TestCase):
    def test_pinned_dispatch_and_recovery_cases(self):
        self.assertEqual(checker.check(), 4)

    def test_crash_recovery_does_not_claim_second_dispatch(self):
        suite = checker.load((checker.ROOT / checker.SOURCE).read_bytes())
        outcome = suite['cases'][3]['expected']
        self.assertEqual(outcome['effects']['dispatch'], 1)
        self.assertEqual(outcome['output']['stages'][1][-1]['state'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
