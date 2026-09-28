"""Registry authority absence and malformed controls cannot be promoted."""

import unittest

import check_current_spec_id02_evidence as checker


class ID02EvidenceTests(unittest.TestCase):
    def test_both_core_reports_preserve_authority_gap(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
