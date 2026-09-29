"""Signed digest and local policy decisions remain separate."""

import unittest

import check_current_spec_policy_admission_vectors as checker


class PolicyAdmissionVectorTests(unittest.TestCase):
    def test_signed_but_unapproved_intents(self):
        self.assertEqual(checker.check(), 2)


if __name__ == '__main__':
    unittest.main()
