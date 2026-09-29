"""Archived Registry proof observations stay tied to pinned binaries."""

import unittest

import check_current_spec_reg04_evidence as checker


class Reg04EvidenceTests(unittest.TestCase):
    def test_proof_observations(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
