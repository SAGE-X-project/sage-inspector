"""Valid-control DID failures cannot certify malformed candidate rejection."""

import unittest

import check_current_spec_id01_evidence as checker


class ID01EvidenceTests(unittest.TestCase):
    def test_both_core_reports_preserve_mismatches(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
