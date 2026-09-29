"""SESSION-06 closure evidence cannot claim full protocol recovery."""

import unittest

import check_current_spec_session06_evidence as checker


class Session06EvidenceTests(unittest.TestCase):
    def test_both_core_reports_preserve_closure_partial_boundary(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][3])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][3])


if __name__ == '__main__':
    unittest.main()
