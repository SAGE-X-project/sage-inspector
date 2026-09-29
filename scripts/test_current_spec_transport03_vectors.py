"""A signed response needs its original request and terminal state."""

import unittest

import check_current_spec_transport03_vectors as checker


class Transport03VectorTests(unittest.TestCase):
    def test_response_request_binding(self):
        self.assertEqual(checker.check(), 7)


if __name__ == '__main__':
    unittest.main()
