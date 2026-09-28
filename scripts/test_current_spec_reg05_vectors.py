"""Freshness cases retain their exact source and trust boundaries."""

import unittest

import check_current_spec_reg05_vectors as checker


class Reg05VectorTests(unittest.TestCase):
    def test_finality_time_and_revocation_cases(self):
        self.assertEqual(checker.check(), (6, 3))


if __name__ == '__main__':
    unittest.main()
