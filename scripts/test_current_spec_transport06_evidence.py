"""Archived event and core observations retain their exact provenance."""

import unittest

import check_current_spec_transport06_evidence as checker


class Transport06EvidenceTests(unittest.TestCase):
    def test_websocket_and_local_receive_observations(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
