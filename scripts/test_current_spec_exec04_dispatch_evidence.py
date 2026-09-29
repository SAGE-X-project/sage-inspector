"""The bounded core sink shows one commit and no repeat after reopen."""

import unittest

import check_current_spec_exec04_dispatch_evidence as checker


class Exec04DispatchEvidenceTests(unittest.TestCase):
    def test_go_and_rust_durable_dispatch(self):
        result = checker.check()
        self.assertEqual(result['go']['PARTIAL'], 4)
        self.assertEqual(result['rust']['PARTIAL'], 4)


if __name__ == '__main__':
    unittest.main()
