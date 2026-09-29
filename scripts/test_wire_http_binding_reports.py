"""Reject false promotion of preserved core observations."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import check_wire_http_binding_reports as audit
from generate_wire_http_binding_suite import OUTPUT, ROOT, SOURCE


class WireHTTPBindingReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for path in (SOURCE, OUTPUT,
                     ROOT / 'docs/evidence/wire-http-binding-go.json',
                     ROOT / 'docs/evidence/wire-http-binding-rust.json'):
            target = self.root / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)

    def test_observed_outcomes_remain_bounded(self):
        self.assertEqual(audit.assess(self.root), {
            'go': {'PASS': 2, 'FAIL': 2, 'UNSUPPORTED': 2, 'NOT_RUN': 0},
            'rust': {'PASS': 4, 'FAIL': 0, 'UNSUPPORTED': 2, 'NOT_RUN': 0},
        })

    def test_go_tag_loss_cannot_be_reclassified_as_pass(self):
        path = self.root / 'docs/evidence/wire-http-binding-go.json'
        report = json.loads(path.read_text())
        report['results'][0]['status'] = 'PASS'
        path.write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            audit.assess(self.root)

    def test_unsupported_boundary_cannot_be_reclassified_as_pass(self):
        path = self.root / 'docs/evidence/wire-http-binding-rust.json'
        report = json.loads(path.read_text())
        report['results'][-1]['status'] = 'PASS'
        path.write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            audit.assess(self.root)

    def test_wrong_suite_hash_fails(self):
        path = self.root / 'docs/evidence/wire-http-binding-rust.json'
        report = json.loads(path.read_text())
        report['suite_sha256'] = '0' * 64
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'report identity'):
            audit.assess(self.root)


if __name__ == '__main__':
    unittest.main()
