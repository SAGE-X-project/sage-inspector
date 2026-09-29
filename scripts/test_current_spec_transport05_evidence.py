"""Archived HTTP observations remain tied to pinned inputs and binaries."""

import unittest

import check_current_spec_transport05_evidence as checker


class Transport05EvidenceTests(unittest.TestCase):
    def test_http_receive_observations(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
