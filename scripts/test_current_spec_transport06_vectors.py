"""The carrier gate and core observations remain distinct."""

import unittest

import check_current_spec_transport06_vectors as checker


class Transport06VectorTests(unittest.TestCase):
    def test_websocket_and_local_adapter_scenarios(self):
        self.assertEqual(checker.check(), (5, 4))


if __name__ == '__main__':
    unittest.main()
