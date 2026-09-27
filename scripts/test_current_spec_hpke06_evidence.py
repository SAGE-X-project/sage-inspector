"""HPKE-06 unimplemented admission must remain visible in both reports."""

import unittest

import check_current_spec_hpke06_evidence as checker


class HPKE06EvidenceTests(unittest.TestCase):
    def test_both_core_reports_reassess_to_unsupported(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
