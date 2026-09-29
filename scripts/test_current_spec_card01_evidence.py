"""A valid reference card does not promote missing core card verification."""

import unittest

import check_current_spec_card01_evidence as checker


class Card01EvidenceTests(unittest.TestCase):
    def test_both_cores_report_missing_card_verifier(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][2])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][2])


if __name__ == '__main__':
    unittest.main()
