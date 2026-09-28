"""Signed invalid envelopes must be rejected by schema, not signature alone."""

import unittest

import check_current_spec_transport01_vectors as checker


class Transport01VectorTests(unittest.TestCase):
    def test_closed_envelope_boundaries(self):
        self.assertEqual(checker.check(), 5)


if __name__ == '__main__':
    unittest.main()
