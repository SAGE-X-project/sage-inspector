"""Guarded RPC route fixtures remain pinned to public request bytes."""

import unittest

import check_current_spec_rpc_route_vectors as checker


class RPCRouteVectorTests(unittest.TestCase):
    def test_route_exclusions(self):
        self.assertEqual(checker.check(), 2)


if __name__ == '__main__':
    unittest.main()
