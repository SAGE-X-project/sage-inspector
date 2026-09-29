"""Pinned client consumption evidence is reproducibly assessed."""

import unittest

import check_current_spec_exec_client_evidence as checker


class ClientConsumptionEvidenceTests(unittest.TestCase):
    def test_go_and_rust_result_consumption(self):
        result = checker.check()
        self.assertEqual(result['go']['PARTIAL'], 4)
        self.assertEqual(result['rust']['PARTIAL'], 4)


if __name__ == '__main__':
    unittest.main()
