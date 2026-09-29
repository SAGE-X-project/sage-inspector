"""Client consumption cases keep independent signed, durable controls."""

import unittest

import check_current_spec_exec_client_vectors as checker


class ClientConsumptionVectorTests(unittest.TestCase):
    def test_pinned_client_cases(self):
        self.assertEqual(checker.check(), 4)

    def test_duplicate_and_expiry_are_distinct(self):
        suite = checker.load((checker.ROOT / checker.SOURCE).read_bytes())
        duplicate = suite['cases'][0]['expected']['output']['scenarios'][
            'late-pending-and-duplicate']['steps']
        expired = suite['cases'][3]['expected']['output']['scenarios'][
            'expired-result']['steps']
        self.assertTrue(duplicate[7]['ignored'])
        self.assertFalse(expired[3]['ok'])


if __name__ == '__main__':
    unittest.main()
