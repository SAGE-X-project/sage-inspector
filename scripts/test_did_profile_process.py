"""Safe native library and owned TLS observations, distinct from unit verdicts."""
import os
import unittest
from unittest.mock import patch
import did_profile_observation as m

class NativeDIDTests(unittest.TestCase):
    def test_actual_processes_and_revision_bound_findings(self):
        r=m.run_native(os.environ.get('SAGE_INSPECTION_GO','go'))
        self.assertEqual(r['status_counts'],{'NOT_RUN':555,'PARTIAL':23,'FAIL':2,'UNSUPPORTED':3})
        self.assertTrue(m.known_gap_only(r))
        self.assertEqual(r['execution']['process_count'],25)
        self.assertEqual(len(r['execution']['raw_trace']),25)
        self.assertEqual(r['scope']['protected_message_authority'],'NOT_RUN')
        self.assertEqual(r['scope']['sage_http_binding'],'NOT_RUN')
        self.assertEqual(r['scope']['deployed_registry'],'NOT_BOUND')
        self.assertEqual(r['evidence_kind'],'inspector-launched-native-DID-processes')
        self.assertEqual({x['id'] for x in r['cases'] if x['status']=='FAIL'},m.KNOWN_GAPS)

    def test_observer_source_drift_rejected(self):
        with patch.object(m,'observer_sources',side_effect=[{'fixture':'before'},{'fixture':'after'}]):
            with self.assertRaisesRegex(ValueError,'observer source changed'):
                m.run_native(os.environ.get('SAGE_INSPECTION_GO','go'))

if __name__=='__main__':unittest.main()
