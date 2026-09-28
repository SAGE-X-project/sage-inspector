"""REG-06 archived observations cannot impersonate deployment evidence."""

import unittest

import check_current_spec_reg06_evidence as checker


class Reg06EvidenceTests(unittest.TestCase):
    def test_runtime_and_deployment_tracks(self):
        self.assertEqual(set(checker.check()), {'go', 'rust'})


if __name__ == '__main__':
    unittest.main()
