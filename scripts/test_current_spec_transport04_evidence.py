"""A failed AEAD primitive cannot prove an atomic replay transaction."""

import unittest

import check_current_spec_transport04_evidence as checker


class Transport04EvidenceTests(unittest.TestCase):
    def test_core_receive_gap_and_failed_tag(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][3])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][3])


if __name__ == '__main__':
    unittest.main()
