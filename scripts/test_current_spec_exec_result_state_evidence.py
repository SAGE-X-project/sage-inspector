"""The cores preserve signed first terminal results and refuse late reads."""

import unittest

import check_current_spec_exec_result_state_evidence as checker


class ExecutionResultStateEvidenceTests(unittest.TestCase):
    def test_go_and_rust_signed_lifecycle(self):
        result = checker.check()
        self.assertEqual(result['go']['PARTIAL'], 3)
        self.assertEqual(result['rust']['PARTIAL'], 3)


if __name__ == '__main__':
    unittest.main()
