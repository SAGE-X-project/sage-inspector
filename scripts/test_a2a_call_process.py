"""Runtime observations through real ADK APIs and owned local TLS fixtures."""
import os
import unittest
from unittest.mock import patch
from a2a_call_observation import run_native, combine
from a2a_card_observation import run_native as run_cards

class NativePolicyTests(unittest.TestCase):
    def test_native_tls_policy_and_card_observations(self):
        go=os.environ.get('SAGE_INSPECTION_GO','go')
        calls=run_native(go)
        self.assertEqual(calls['status_counts'],{'PARTIAL':20,'UNSUPPORTED':3,'NOT_RUN':560})
        self.assertEqual(calls['execution']['process_count'],20)
        self.assertEqual(calls['execution']['runtime'],'owned-loopback-TLS-policy-fixture')
        self.assertEqual(len(calls['execution']['raw_trace']),20)
        full=combine(run_cards(go),calls)
        self.assertEqual(full['status_counts'],{'PARTIAL':61,'UNSUPPORTED':3,'NOT_RUN':519})
        self.assertEqual(full['scope']['signed_carriage'],'NOT_RUN')
        self.assertEqual(full['scope']['deployed_registry'],'NOT_BOUND')

    def test_runtime_source_changes_rejected(self):
        with patch('a2a_call_observation.observer_sources',side_effect=[{'fixture':'before'},{'fixture':'after'}]):
            with self.assertRaisesRegex(ValueError,'observer source changed'):
                run_native(os.environ.get('SAGE_INSPECTION_GO','go'))

if __name__=='__main__':unittest.main()
