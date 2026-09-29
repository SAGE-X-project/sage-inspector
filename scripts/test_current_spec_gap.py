"""Ensure historical related evidence is never counted as current conformance."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import current_spec_gap as gap


class CurrentSpecGapTests(unittest.TestCase):
    def test_all_cases_and_prior_evidence_are_separate(self):
        report = gap.assess()
        self.assertEqual(len(report['cases']), 481)
        self.assertEqual(report['case_counts'], {'baseline': 386, 'mcp_binding': 71,
                                                 'registry_clarification': 8,
                                                 'later_spec_correction': 16})
        self.assertEqual(report['mandatory_subscenario_count'], 26)
        self.assertEqual(report['historical_primitive_candidates'], 8)
        self.assertEqual(report['current_complete_bindings'], 0)
        self.assertEqual(report['current_partial_bindings'], 337)
        self.assertEqual({row['current_case_status'] for row in report['cases']}, {'NOT_RUN'})
        self.assertFalse(any(row['current_complete_binding'] for row in report['cases']))
        self.assertEqual(len({row['id'] for row in report['cases']}), 481)

    def test_registry_partial_observation_is_not_full_case(self):
        report = gap.assess()
        rows = {row['id']: row for row in report['cases']}
        self.assertEqual(rows['mllm-pop-exact-bytes']['related_historical_evidence'][0]['kind'],
                         'partial_prior_revision_byte_observation')
        self.assertEqual(rows['mllm-pop-exact-bytes']['current_case_status'], 'NOT_RUN')
        self.assertEqual(rows['merrata-config-valid']['related_historical_evidence'], [])
        self.assertEqual(rows['JCS-01-N01']['bound_tracks'], {'runtime': 'partial'})

    def test_cli_writes_complete_machine_readable_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            proc = subprocess.run([sys.executable, '-B', str(gap.ROOT / 'scripts/current_spec_gap.py'),
                                   '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(len(json.loads(output.read_text())['cases']), 481)


if __name__ == '__main__':
    unittest.main()
