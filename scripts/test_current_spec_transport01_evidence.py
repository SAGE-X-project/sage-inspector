"""Generic signature success cannot certify closed transport schema."""

import unittest

import check_current_spec_transport01_evidence as checker


class Transport01EvidenceTests(unittest.TestCase):
    def test_core_envelope_gap_and_signature_primitives(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][3])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][3])


if __name__ == '__main__':
    unittest.main()
