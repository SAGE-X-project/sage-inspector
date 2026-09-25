"""Guard the Inspector registry-proof report against unsupported PASS claims."""

import unittest

from test_registry_proof010 import CASE_IDS, case_statuses


class RegistryProofReportTests(unittest.TestCase):
    def test_only_exact_byte_case_is_partial(self):
        cases = case_statuses()
        self.assertEqual(set(cases), set(CASE_IDS))
        self.assertEqual([case for case, result in cases.items()
                          if result['status'] == 'PARTIAL'], ['mllm-pop-exact-bytes'])
        self.assertEqual(sum(result['status'] == 'NOT_RUN' for result in cases.values()), 7)
        self.assertTrue(all(result['status'] != 'PASS' for result in cases.values()))


if __name__ == '__main__':
    unittest.main()
