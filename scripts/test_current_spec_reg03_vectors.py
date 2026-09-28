"""Registry lifecycle expectations follow the source state sequence."""

import unittest

import check_current_spec_reg03_vectors as checker


class Reg03VectorTests(unittest.TestCase):
    def test_atomic_lifecycle_and_no_effect_rejections(self):
        self.assertEqual(checker.check(), (5, 2))


if __name__ == '__main__':
    unittest.main()
