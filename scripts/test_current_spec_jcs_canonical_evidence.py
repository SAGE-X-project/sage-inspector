"""The cumulative JCS byte run remains independently reassessable."""

import unittest

import check_current_spec_jcs_canonical_evidence as checker


class PreservedJCSCanonicalEvidenceTests(unittest.TestCase):
    def test_go_and_rust_counts(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
