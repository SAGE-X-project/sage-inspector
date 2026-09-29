"""Pinned Go and Rust Guard denial evidence remains partial and reproducible."""

import unittest

import check_current_spec_exec_denial_evidence as checker


class ExecutionDenialEvidenceTests(unittest.TestCase):
    def test_go_and_rust_denials(self):
        result = checker.check()
        self.assertEqual(result['go']['PARTIAL'], 3)
        self.assertEqual(result['rust']['PARTIAL'], 3)


if __name__ == '__main__':
    unittest.main()
