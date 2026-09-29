"""Guard denial fixtures preserve zero-effect assertions."""

import unittest

import check_current_spec_exec_denial_vectors as checker


class ExecutionDenialVectorTests(unittest.TestCase):
    def test_pinned_policy_resolver_and_retirement_denials(self):
        self.assertEqual(checker.check(), 3)


if __name__ == '__main__':
    unittest.main()
