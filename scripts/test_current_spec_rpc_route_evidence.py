"""Archived guarded RPC route results remain reproducible."""

import unittest

import check_current_spec_rpc_route_evidence as checker


class RPCRouteEvidenceTests(unittest.TestCase):
    def test_both_cores(self):
        rows = checker.check()
        self.assertEqual(set(rows), {'go', 'rust'})
        self.assertTrue(all(row['PARTIAL'] == 2 for row in rows.values()))


if __name__ == '__main__':
    unittest.main()
