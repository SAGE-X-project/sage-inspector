"""Preserved process observations cannot establish full spec conformance."""

import unittest

from check_current_spec_process_evidence import check


class ProcessEvidenceTests(unittest.TestCase):
    def test_pinned_review_remains_partial(self):
        self.assertEqual(check(), 9)


if __name__ == '__main__':
    unittest.main()
