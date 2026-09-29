"""SESSION-04 fixtures retain independent send-allocation relations."""

import unittest

import check_current_spec_session04_vectors as checker


class Session04VectorTests(unittest.TestCase):
    def test_concurrency_failure_retransmission_and_mac_boundary(self):
        self.assertEqual(checker.check(), 4)


if __name__ == '__main__':
    unittest.main()
