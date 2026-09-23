"""Prevent unconfigured registry evidence from becoming a live-chain PASS."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import check_registry_source_deployment_audit as audit


class DeploymentAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name) / 'evidence'
        shutil.copytree(audit.EVIDENCE, self.base)

    def tearDown(self):
        self.temporary.cleanup()

    def manifest(self):
        return json.loads((self.base / 'manifest.json').read_text())

    def save(self, manifest):
        (self.base / 'manifest.json').write_text(json.dumps(manifest) + '\n')

    def test_saved_no_binding_result(self):
        self.assertEqual(audit.check(self.base)['status'], 'NOT_RUN')

    def test_report_tampering(self):
        report = self.base / 'unconfigured-report.json'
        report.write_bytes(report.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'hash'):
            audit.check(self.base)

    def test_process_output_tampering(self):
        output = self.base / 'unconfigured.stdout'
        output.write_bytes(output.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'process output'):
            audit.check(self.base)

    def test_report_claim_promotion(self):
        manifest = self.manifest()
        report = self.base / 'unconfigured-report.json'
        value = json.loads(report.read_text())
        value['live_chain_verification'] = 'PASS'
        raw = (json.dumps(value) + '\n').encode()
        report.write_bytes(raw)
        manifest['runtime']['report_sha256'] = audit.sha(raw)
        self.save(manifest)
        with self.assertRaisesRegex(ValueError, 'promoted'):
            audit.check(self.base)

    def test_candidate_claim_promotion(self):
        manifest = self.manifest()
        manifest['readme_candidate']['status'] = 'VERIFIED'
        self.save(manifest)
        with self.assertRaisesRegex(ValueError, 'candidate'):
            audit.check(self.base)


if __name__ == '__main__':
    unittest.main()
