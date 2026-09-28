"""Legacy parser acceptance cannot become reserved-profile conformance."""

import unittest

import check_current_spec_reg07_evidence as checker


class Reg07EvidenceTests(unittest.TestCase):
    def test_reserved_profile_observations(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
