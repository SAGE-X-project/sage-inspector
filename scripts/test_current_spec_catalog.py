"""Inventory integrity controls for the complete current spec catalog."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import current_spec_catalog as checker


class CurrentSpecCatalogTests(unittest.TestCase):
    def test_complete_inventory_and_special_child_mapping(self):
        manifest, trace, mapped = checker.catalog()
        self.assertEqual(manifest['counts'], {
            'requirements': 45, 'rules': 91, 'cases': 481,
            'mandatory_subscenarios': 26, 'historical_cases': 386,
            'additional_cases': 95})
        self.assertEqual(set(mapped), {case['id'] for case in trace['cases']})
        for prefix in ('merrata-', 'mrevision-', 'mllm-', 'mstand-'):
            self.assertTrue(any(case_id.startswith(prefix) for case_id in mapped))
        proposal = checker.ROOT / 'verification/0.10.0/mcp-consolidated-proposal'
        historical_mcp = {case['id'] for name in ('cases.json', 'addendum-cases.json',
                                                   'resolutions.json')
                          for case in json.loads((proposal / name).read_text())['cases']}
        self.assertEqual(len(historical_mcp), 71)
        self.assertTrue(historical_mcp <= set(mapped))
        self.assertEqual(len(next(rule for rule in trace['rules']
                                  if rule['id'] == 'MOWN-06')['case_ids']), 8)

    def test_missing_and_false_promoted_cases_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / 'verification/0.10.0'
            current = base / 'current-spec'
            current.mkdir(parents=True)
            for name in ('manifest.json', 'traceability.json', 'additional-case-map.json'):
                (current / name).write_bytes((checker.BASE / name).read_bytes())
            (base / 'case-map.json').write_bytes(checker.HISTORICAL.read_bytes())
            checker.catalog(root)
            additions = json.loads((current / 'additional-case-map.json').read_text())
            (current / 'additional-case-map.json').write_text(json.dumps(additions[:-1]))
            with self.assertRaisesRegex(ValueError, 'unmapped or obsolete cases'):
                checker.catalog(root)
            additions[-1]['evidence_status'] = 'PASS'
            (current / 'additional-case-map.json').write_text(json.dumps(additions))
            with self.assertRaisesRegex(ValueError, 'falsely promoted'):
                checker.catalog(root)

    def test_source_revision_and_hash_drift_fail(self):
        manifest = json.loads((checker.BASE / 'manifest.json').read_text())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'verification').mkdir()
            (root / 'verification/traceability.json').write_bytes(
                (checker.BASE / 'traceability.json').read_bytes())
            for relative in manifest['source_sha256']:
                path = root / relative
                if not path.exists():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'changed source\n')
            with mock.patch.object(checker.subprocess, 'check_output', return_value='0' * 40):
                with self.assertRaisesRegex(ValueError, 'source spec revision drift'):
                    checker.catalog(spec_root=root)
            with mock.patch.object(checker.subprocess, 'check_output',
                                   return_value=manifest['spec_revision']):
                with self.assertRaisesRegex(ValueError, 'source spec file drift'):
                    checker.catalog(spec_root=root)

    def test_cli_report_is_complete_and_never_claims_conformance(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / 'report.json'
            result = subprocess.run([sys.executable, '-B', str(checker.ROOT / 'scripts/current_spec_catalog.py'),
                                     '--report', str(report_path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(report_path.read_text())
            self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
            self.assertEqual(report['counts']['case_not_run'], 481)
            self.assertEqual(len(report['cases']), 481)
            self.assertTrue(all(case['status'] == 'NOT_RUN' for case in report['cases']))


if __name__ == '__main__':
    unittest.main()
