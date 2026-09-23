"""Keep absent host observations distinct from successful host enforcement."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import check_agent_host_deployment_audit as audit


class AgentHostAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name) / 'evidence'
        shutil.copytree(audit.EVIDENCE, self.base)

    def tearDown(self):
        self.temporary.cleanup()

    def test_archived_unconfigured_result(self):
        self.assertEqual(audit.check(self.base)['status'], 'NOT_RUN')

    def test_report_bytes_cannot_change(self):
        report = self.base / 'unconfigured/summary.json'
        report.write_bytes(report.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'hash'):
            audit.check(self.base)

    def test_observed_effects_cannot_be_invented(self):
        manifest_file = self.base / 'manifest.json'
        manifest = json.loads(manifest_file.read_text())
        report_file = self.base / 'unconfigured/summary.json'
        report = json.loads(report_file.read_text())
        report['scenarios'][0]['observed_effects'] = []
        raw = (json.dumps(report) + '\n').encode()
        report_file.write_bytes(raw)
        manifest['runtime']['report_sha256'] = audit.sha(raw)
        manifest_file.write_text(json.dumps(manifest) + '\n')
        with self.assertRaisesRegex(ValueError, 'promoted'):
            audit.check(self.base)

    def test_missing_host_cannot_be_promoted(self):
        manifest_file = self.base / 'manifest.json'
        manifest = json.loads(manifest_file.read_text())
        manifest['status'] = 'PASS'
        manifest_file.write_text(json.dumps(manifest) + '\n')
        with self.assertRaisesRegex(ValueError, 'promoted'):
            audit.check(self.base)

    def test_scenario_membership_cannot_change(self):
        manifest_file = self.base / 'manifest.json'
        manifest = json.loads(manifest_file.read_text())
        report_file = self.base / 'unconfigured/summary.json'
        report = json.loads(report_file.read_text())
        report['scenarios'][0]['id'] = 'other-host'
        raw = (json.dumps(report) + '\n').encode()
        report_file.write_bytes(raw)
        manifest['runtime']['report_sha256'] = audit.sha(raw)
        manifest_file.write_text(json.dumps(manifest) + '\n')
        with self.assertRaisesRegex(ValueError, 'promoted'):
            audit.check(self.base)


if __name__ == '__main__':
    unittest.main()
