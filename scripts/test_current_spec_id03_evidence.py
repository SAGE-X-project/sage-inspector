"""Full named-key authentication stays unsupported despite state evidence."""

import unittest

import check_current_spec_id03_evidence as checker


class ID03EvidenceTests(unittest.TestCase):
    def test_core_reports_keep_state_prerequisites_separate(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][3])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][3])


if __name__ == '__main__':
    unittest.main()
