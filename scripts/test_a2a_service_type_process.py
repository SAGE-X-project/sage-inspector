"""Safe real card verifier processes with a paired signed-card control."""
import os
import unittest
from unittest.mock import patch
import a2a_service_type_observation as m

class NativeServiceTests(unittest.TestCase):
    def test_real_service_pair_and_fresh_a2a_components(self):
        go=os.environ.get('SAGE_INSPECTION_GO','go');s=m.run_native(go)
        self.assertEqual(s['status_counts'],{'NOT_RUN':581,'PARTIAL':2})
        self.assertEqual(s['execution']['process_count'],2)
        self.assertEqual(len(s['execution']['raw_trace']),2)
        self.assertEqual(s['evidence_kind'],'inspector-launched-native-service-type-processes')
        a=m.combine_calls(m.run_cards(go),m.run_calls(go));report=m.combine(a,s)
        self.assertEqual(report['status_counts'],{'PARTIAL':63,'UNSUPPORTED':3,'NOT_RUN':517})
        self.assertEqual(report['subject']['revision'],m.ADK_REVISION)
        self.assertEqual(report['scope']['signed_carriage'],'NOT_RUN')

    def test_observer_source_drift_rejected(self):
        with patch.object(m,'observer_sources',side_effect=[{'fixture':'before'},{'fixture':'after'}]):
            with self.assertRaisesRegex(ValueError,'observer source changed'):m.run_native(os.environ.get('SAGE_INSPECTION_GO','go'))

if __name__=='__main__':unittest.main()
