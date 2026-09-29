"""Keep Registry key-selection defects isolated from adapter outcomes."""

import unittest

import check_current_spec_reg02_vectors as checker


class Reg02VectorTests(unittest.TestCase):
    def test_selection_role_and_immutable_identity(self):
        self.assertEqual(checker.check(), (4, 3))


if __name__ == '__main__':
    unittest.main()
