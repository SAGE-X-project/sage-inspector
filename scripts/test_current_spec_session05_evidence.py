"""SESSION-05 primitive and stateful scopes must stay separate."""

import unittest

import check_current_spec_session05_evidence as checker


class Session05EvidenceTests(unittest.TestCase):
    def test_both_core_reports_preserve_stateful_partial_boundaries(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][3])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][3])


if __name__ == '__main__':
    unittest.main()
