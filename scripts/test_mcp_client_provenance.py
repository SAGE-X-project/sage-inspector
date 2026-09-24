"""Reject forged or over-promoted MCP core boundary evidence."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import check_mcp_client_provenance as evidence


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name) / 'evidence'
        shutil.copytree(evidence.EVIDENCE, self.base)

    def tearDown(self):
        self.temporary.cleanup()

    def report(self):
        return json.loads((self.base / 'report.json').read_text())

    def save(self, report):
        (self.base / 'report.json').write_text(json.dumps(report) + '\n')

    def test_pinned_core_observation_remains_incomplete(self):
        result = evidence.check(self.base)
        self.assertEqual(result['status'], 'CORE_BOUNDARY_OBSERVED')
        self.assertEqual(result['deployed_host'], 'NOT_RUN')

    def test_host_cannot_be_promoted(self):
        report = self.report()
        report['deployed_host'] = 'PASS'
        self.save(report)
        with self.assertRaisesRegex(ValueError, 'promoted'):
            evidence.check(self.base)

    def test_conformance_cannot_be_promoted(self):
        report = self.report()
        report['conformance'] = 'PASS'
        self.save(report)
        with self.assertRaisesRegex(ValueError, 'promoted'):
            evidence.check(self.base)

    def test_test_inventory_cannot_expand(self):
        report = self.report()
        report['cases']['synthetic-host-pass'] = report['cases']['go-root']
        self.save(report)
        with self.assertRaisesRegex(ValueError, 'inventory'):
            evidence.check(self.base)

    def test_core_revision_cannot_change(self):
        report = self.report()
        report['sources']['rust']['revision'] = '0' * 40
        self.save(report)
        with self.assertRaisesRegex(ValueError, 'source inventory'):
            evidence.check(self.base)

    def test_log_cannot_change(self):
        log = self.base / 'go-root.stdout'
        log.write_bytes(log.read_bytes() + b'PASS host\n')
        with self.assertRaisesRegex(ValueError, 'log hash'):
            evidence.check(self.base)

    def test_false_success_with_matching_hash_is_rejected(self):
        report = self.report()
        raw = b'ok  github.com/sage-x-project/sage/pkg/agent/guard010 0.001s\n'
        (self.base / 'go-root.stdout').write_bytes(raw)
        report['cases']['go-root']['stdout_sha256'] = evidence.sha(raw)
        self.save(report)
        with self.assertRaisesRegex(ValueError, 'test outcome'):
            evidence.check(self.base)


if __name__ == '__main__':
    unittest.main()
