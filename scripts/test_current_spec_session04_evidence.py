"""SESSION-04 missing stateful support must remain explicit."""

import unittest

import check_current_spec_session04_evidence as checker


class Session04EvidenceTests(unittest.TestCase):
    def test_both_core_reports_keep_all_cases_unsupported(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
