"""HPKE-01 cases preserve the RFC anchor and isolated role conditions."""

import unittest

import check_current_spec_hpke01_vectors as checker


class HPKE01VectorTests(unittest.TestCase):
    def test_four_suite_and_key_role_cases(self):
        self.assertEqual(checker.check(), 4)


if __name__ == '__main__':
    unittest.main()
