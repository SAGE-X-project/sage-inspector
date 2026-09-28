"""No card freshness result is promoted from an unavailable verifier."""

import unittest

import check_current_spec_card03_evidence as checker


class Card03EvidenceTests(unittest.TestCase):
    def test_core_card_freshness_gap(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][3])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][3])


if __name__ == '__main__':
    unittest.main()
