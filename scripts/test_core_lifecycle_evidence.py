"""The INS-11 evidence checker rejects changed bytes and inflated verdicts."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import check_core_lifecycle_evidence as checker


class LifecycleEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name) / 'evidence'
        shutil.copytree(checker.EVIDENCE, self.base)

    def tearDown(self):
        self.temporary.cleanup()

    def manifest(self):
        return json.loads((self.base / 'manifest.json').read_text())

    def save(self, manifest):
        (self.base / 'manifest.json').write_text(json.dumps(manifest) + '\n')

    def test_saved_evidence(self):
        self.assertEqual(checker.check(self.base)['status'], 'EVIDENCE_CHECKED')

    def test_modified_log(self):
        manifest = self.manifest()
        log = self.base / manifest['subjects']['go']['log']
        log.write_bytes(log.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'hash'):
            checker.check(self.base)

    def test_historical_promotion(self):
        manifest = self.manifest()
        manifest['historical']['legacy_go_close_race'] = 'PASS'
        self.save(manifest)
        with self.assertRaisesRegex(ValueError, 'historical'):
            checker.check(self.base)

    def test_replay_status_promotion(self):
        manifest = self.manifest()
        path = self.base / manifest['replay']['report']
        report = json.loads(path.read_text())
        report['conformance'] = 'PASS'
        raw = (json.dumps(report) + '\n').encode()
        path.write_bytes(raw)
        manifest['replay']['report_sha256'] = checker.sha(raw)
        self.save(manifest)
        with self.assertRaisesRegex(ValueError, 'replay report'):
            checker.check(self.base)


if __name__ == '__main__':
    unittest.main()
