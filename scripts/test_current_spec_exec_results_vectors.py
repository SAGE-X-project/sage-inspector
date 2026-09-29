"""Signed result and MCP representation examples remain independently pinned."""

import unittest

import check_current_spec_exec_results_vectors as checker


class ExecutionResultVectorTests(unittest.TestCase):
    def test_pinned_result_and_manifest_cases(self):
        self.assertEqual(checker.check(), 9)

    def test_issuer_mutation_has_valid_signature(self):
        suite = checker.load((checker.ROOT / checker.SOURCE).read_bytes())
        self.assertTrue(checker.signature_valid(suite['cases'][3]['input']['input']))
        self.assertFalse(checker.signature_valid(suite['cases'][6]['input']['input']))


if __name__ == '__main__':
    unittest.main()
