"""SESSION-03 bounded record matches must stay partial evidence."""

import unittest

import check_current_spec_session03_evidence as checker


class Session03EvidenceTests(unittest.TestCase):
    def test_both_core_reports_reassess_to_partial(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
