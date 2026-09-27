"""SESSION-03 fixtures retain independent record and bound relations."""

import unittest

import check_current_spec_session03_vectors as checker


class Session03VectorTests(unittest.TestCase):
    def test_record_nonce_direction_and_aad_boundaries(self):
        self.assertEqual(checker.check(), 8)


if __name__ == '__main__':
    unittest.main()
