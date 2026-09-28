"""Archived Registry observation results remain tied to pinned binaries."""

import unittest

import check_current_spec_reg05_evidence as checker


class Reg05EvidenceTests(unittest.TestCase):
    def test_observation_results(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
