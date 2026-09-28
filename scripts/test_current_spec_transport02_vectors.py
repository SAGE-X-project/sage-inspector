"""Every request field must be covered by the inner signature."""

import unittest

import check_current_spec_transport02_vectors as checker


class Transport02VectorTests(unittest.TestCase):
    def test_request_signature_coverage(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
