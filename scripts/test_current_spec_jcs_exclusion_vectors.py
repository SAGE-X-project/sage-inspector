"""Agent Card fixtures retain a valid signed control and one mutation each."""

import unittest

import check_current_spec_jcs_exclusion_vectors as checker


class JCSExclusionVectorTests(unittest.TestCase):
    def test_valid_control_and_three_exact_mutations(self):
        self.assertEqual(checker.check(), 4)


if __name__ == '__main__':
    unittest.main()
