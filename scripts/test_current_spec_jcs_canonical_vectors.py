"""JCS byte relation vectors encode distinct required properties."""

import unittest

import check_current_spec_jcs_canonical_vectors as checker


class JCSCanonicalVectorTests(unittest.TestCase):
    def test_all_four_byte_relations(self):
        self.assertEqual(checker.check(), 4)


if __name__ == '__main__':
    unittest.main()
