"""Inner signature results do not prove request admission or key ownership."""

import unittest

import check_current_spec_transport02_evidence as checker


class Transport02EvidenceTests(unittest.TestCase):
    def test_core_request_gap_and_signature_primitives(self):
        result = checker.check()
        self.assertEqual(result['go'], checker.REVISIONS['go'][3])
        self.assertEqual(result['rust'], checker.REVISIONS['rust'][3])


if __name__ == '__main__':
    unittest.main()
