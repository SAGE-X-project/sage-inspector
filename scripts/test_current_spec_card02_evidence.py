"""Generic signature results cannot certify the Agent Card proof profile."""

import unittest

import check_current_spec_card02_evidence as checker


class Card02EvidenceTests(unittest.TestCase):
    def test_core_card_verifier_gap_and_signature_primitives(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][3])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][3])


if __name__ == '__main__':
    unittest.main()
