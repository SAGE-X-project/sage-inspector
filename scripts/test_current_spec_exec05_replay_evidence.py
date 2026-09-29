"""The Go and Rust durable gates reject changed retry identities."""

import unittest

import check_current_spec_exec05_replay_evidence as checker


class Exec05ReplayEvidenceTests(unittest.TestCase):
    def test_go_and_rust_replay_outcomes(self):
        result = checker.check()
        self.assertEqual(result['go']['PARTIAL'], 4)
        self.assertEqual(result['rust']['PARTIAL'], 4)


if __name__ == '__main__':
    unittest.main()
