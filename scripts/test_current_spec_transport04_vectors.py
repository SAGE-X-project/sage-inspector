"""Replay and dispatch expectations stay unit-only for these scenarios."""

import unittest

import check_current_spec_transport04_vectors as checker


class Transport04VectorTests(unittest.TestCase):
    def test_receive_reservation_scenarios(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
