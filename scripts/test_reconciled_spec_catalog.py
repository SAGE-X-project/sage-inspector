"""Keep the revised normative source separate from old Inspector evidence."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import reconciled_spec_catalog as checker


class ReconciledSpecCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        base = 'verification/0.10.0/'
        for name in ('current-spec', 'latest-spec', 'reconciled-spec'):
            for filename in ('manifest.json', 'traceability.json',
                             'additional-case-map.json'):
                relative = base + name + '/' + filename
                target = self.root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(checker.ROOT / relative, target)
        relative = base + 'case-map.json'
        shutil.copyfile(checker.ROOT / relative, self.root / relative)

    def test_exact_489_case_snapshot_without_inherited_results(self):
        report = checker.assess(self.root)
        self.assertEqual(report['spec_revision'], checker.REVISION)
        self.assertEqual(report['counts']['case_not_run'], 489)
        self.assertEqual(report['counts']['mandatory_subscenario_not_run'], 26)
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')

    def test_old_snapshot_remains_unchanged(self):
        previous = self.root / checker.LATEST_BASE / 'manifest.json'
        value = json.loads(previous.read_bytes())
        value['source_sha256'][checker.REGISTRY_SOURCE] = checker.REGISTRY_SHA256
        previous.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'reconciled source delta'):
            checker.assess(self.root)

    def test_new_source_or_verdict_cannot_drift(self):
        manifest = self.root / checker.BASE / 'manifest.json'
        value = json.loads(manifest.read_bytes())
        value['source_sha256']['spec/03-rfc9421.md'] = '0' * 64
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'reconciled source delta'):
            checker.assess(self.root)
        shutil.copyfile(checker.ROOT / checker.BASE / 'manifest.json', manifest)
        cases = self.root / checker.BASE / 'additional-case-map.json'
        rows = json.loads(cases.read_bytes())
        rows[0]['evidence_status'] = 'PASS'
        cases.write_text(json.dumps(rows))
        with self.assertRaises(ValueError):
            checker.assess(self.root)

    def test_cli_writes_incomplete_report(self):
        output = self.root / 'report.json'
        result = subprocess.run([
            sys.executable, '-B', str(checker.ROOT / 'scripts/reconciled_spec_catalog.py'),
            '--report', str(output)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_bytes())['counts']['case_not_run'], 489)


if __name__ == '__main__':
    unittest.main()
