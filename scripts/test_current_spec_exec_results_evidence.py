"""Both cores match bounded signed-result and MCP representation fixtures."""

import unittest

import check_current_spec_exec_results_evidence as checker


class ExecutionResultEvidenceTests(unittest.TestCase):
    def test_go_and_rust_results(self):
        result = checker.check()
        self.assertEqual(result['go']['PARTIAL'], 9)
        self.assertEqual(result['rust']['PARTIAL'], 9)


if __name__ == '__main__':
    unittest.main()
