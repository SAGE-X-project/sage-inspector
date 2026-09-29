"""SESSION-02 cases retain independent key and clock relations."""

import unittest

import check_current_spec_session02_vectors as checker


class Session02VectorTests(unittest.TestCase):
    def test_directional_rekey_and_lifetime_boundaries(self):
        self.assertEqual(checker.check(), 6)


if __name__ == '__main__':
    unittest.main()
