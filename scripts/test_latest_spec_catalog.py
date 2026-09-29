"""Keep the new specification inventory separate from prior evidence."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import latest_spec_catalog as checker


class LatestSpecCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        base = checker.ROOT / 'verification/0.10.0'
        for name in ('current-spec', 'latest-spec'):
            source = base / name
            target = self.root / 'verification/0.10.0' / name
            target.mkdir(parents=True)
            for filename in ('manifest.json', 'traceability.json',
                             'additional-case-map.json'):
                shutil.copyfile(source / filename, target / filename)
        shutil.copyfile(base / 'case-map.json',
                        self.root / 'verification/0.10.0/case-map.json')

    def test_exact_delta_and_no_inherited_verdicts(self):
        report = checker.assess(self.root)
        self.assertEqual(report['counts']['cases'], 489)
        self.assertEqual(report['counts']['case_not_run'], 489)
        self.assertEqual(set(report['added_case_ids']), checker.NEW_IDS)
        self.assertEqual(sum(not row['previous_revision_presence']
                             for row in report['cases']), 8)
        self.assertTrue(all(row['status'] == 'NOT_RUN' for row in report['cases']))
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')

    def test_added_case_cannot_claim_old_evidence(self):
        path = self.root / checker.LATEST_BASE / 'additional-case-map.json'
        rows = json.loads(path.read_text())
        next(row for row in rows if row['id'] == 'msca-http-ed25519')[
            'evidence_status'] = 'PASS'
        path.write_text(json.dumps(rows))
        with self.assertRaisesRegex(ValueError, 'falsely promoted'):
            checker.assess(self.root)

    def test_missing_latest_case_is_detected(self):
        path = self.root / checker.LATEST_BASE / 'additional-case-map.json'
        rows = json.loads(path.read_text())
        path.write_text(json.dumps([row for row in rows
                                    if row['id'] != 'msca-http-ed25519']))
        with self.assertRaisesRegex(ValueError, 'unmapped or obsolete cases'):
            checker.assess(self.root)

    def test_revision_and_old_snapshot_are_pinned(self):
        path = self.root / checker.LATEST_BASE / 'manifest.json'
        manifest = json.loads(path.read_text())
        manifest['spec_revision'] = checker.OLD_REVISION
        path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            checker.assess(self.root)

    def test_cli_writes_complete_incomplete_report(self):
        output = self.root / 'report.json'
        result = subprocess.run([
            sys.executable, '-B', str(checker.ROOT / 'scripts/latest_spec_catalog.py'),
            '--report', str(output)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(output.read_bytes())
        self.assertEqual(len(report['cases']), 489)
        self.assertEqual(report['status'], 'INVENTORY_ONLY')
        self.assertEqual(report['counts']['mandatory_subscenario_not_run'], 26)


if __name__ == '__main__':
    unittest.main()
