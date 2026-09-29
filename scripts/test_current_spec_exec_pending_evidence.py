"""Archived Client and MCP pending observations remain reproducible."""

import unittest

import check_current_spec_exec_pending_evidence as checker


class PendingEvidenceTests(unittest.TestCase):
    def test_go_and_rust_pending_boundaries(self):
        result = checker.check()
        self.assertTrue(all(row['PARTIAL'] == 1 for row in result.values()))


if __name__ == '__main__':
    unittest.main()
