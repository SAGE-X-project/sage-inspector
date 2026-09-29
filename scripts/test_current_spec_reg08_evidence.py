"""Archived web observations cannot turn an undefined media rule into PASS."""

import unittest

import check_current_spec_reg08_evidence as checker


class Reg08EvidenceTests(unittest.TestCase):
    def test_web_authority_and_media_gap(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
