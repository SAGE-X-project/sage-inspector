"""Preserve the positive-control failure and unsupported key URL status."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import check_did_prefix_reports as audit
from generate_did_prefix_suite import OUTPUT, ROOT


class DIDPrefixReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in (OUTPUT, 'verification/0.10.0/case-map.json',
                         'docs/evidence/did-prefix-go.json',
                         'docs/evidence/did-prefix-rust.json'):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        for name in ('manifest.json', 'traceability.json',
                     'additional-case-map.json'):
            relative = 'verification/0.10.0/latest-spec/' + name
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)

    def test_observed_gaps_remain_visible(self):
        reports = audit.assess(self.root)
        self.assertEqual(reports['go'], {'PASS': 2, 'FAIL': 1,
                                         'UNSUPPORTED': 3, 'NOT_RUN': 0})
        self.assertEqual(reports['rust'], reports['go'])

    def test_rejected_positive_control_cannot_be_promoted(self):
        path = self.root / 'docs/evidence/did-prefix-go.json'
        report = json.loads(path.read_bytes())
        report['results'][0]['status'] = 'PASS'
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'canonical DID control'):
            audit.assess(self.root)

    def test_unsupported_url_cannot_be_promoted(self):
        path = self.root / 'docs/evidence/did-prefix-rust.json'
        report = json.loads(path.read_bytes())
        report['results'][3]['status'] = 'PASS'
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'DID URL support'):
            audit.assess(self.root)


if __name__ == '__main__':
    unittest.main()
