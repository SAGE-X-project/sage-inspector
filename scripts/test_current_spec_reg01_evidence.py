"""Archived record evidence stays bound to the pinned sources and binaries."""

import unittest

import check_current_spec_reg01_evidence as checker


class Reg01EvidenceTests(unittest.TestCase):
    def test_registry_record_observations(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
