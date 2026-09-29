"""Missing Agent Card adapters remain explicitly unsupported."""

import unittest

import check_current_spec_jcs_exclusion_evidence as checker


class PreservedJCSExclusionEvidenceTests(unittest.TestCase):
    def test_both_core_reports_preserve_unsupported_status(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
