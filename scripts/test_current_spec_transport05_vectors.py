"""Static HTTP joint-acceptance expectations are separate from core results."""

import unittest

import check_current_spec_transport05_vectors as checker


class Transport05VectorTests(unittest.TestCase):
    def test_http_dual_signature_and_projection_cases(self):
        self.assertEqual(checker.check(), 9)


if __name__ == '__main__':
    unittest.main()
