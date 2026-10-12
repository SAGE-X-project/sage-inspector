"""Run the real pinned card adapter; no synthetic pass is admitted here."""
import os
import unittest
from a2a_card_observation import run_native

class NativeCardTests(unittest.TestCase):
    def test_native_library_card_boundaries(self):
        report=run_native(os.environ.get('SAGE_INSPECTION_GO','go'))
        self.assertEqual(report['evidence_kind'],'inspector-launched-native-card-processes')
        self.assertEqual(report['execution']['process_count'],41)
        self.assertEqual(report['status_counts'],{'PARTIAL':41,'NOT_RUN':542})
        self.assertEqual(len(report['execution']['raw_trace']),41)
        self.assertTrue(all('stdout_hex' in x for x in report['execution']['raw_trace']))
        self.assertEqual(report['scope']['protected_transport'],'NOT_RUN')

    def test_observer_source_change_during_run_is_rejected(self):
        from unittest.mock import patch
        with patch('a2a_card_observation.observer_sources',side_effect=[{'test':'before'},{'test':'after'}]):
            with self.assertRaisesRegex(ValueError,'observer source changed'):
                run_native(os.environ.get('SAGE_INSPECTION_GO','go'))

if __name__=='__main__':unittest.main()
