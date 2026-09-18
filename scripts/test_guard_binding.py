"""Contract tampering tests and actual bounded CLI execution, without tool dispatch."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from inspect_guard_binding import ROOT, CONTRACT, SPEC, RECORDS, MANIFEST, audit


class GuardBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in (CONTRACT, SPEC, RECORDS, MANIFEST):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        shutil.copytree(ROOT / 'vectors/0.10.0/guard-scenarios', self.root / 'vectors/0.10.0/guard-scenarios')
        self.contract = json.loads((self.root / CONTRACT).read_text())

    def test_complete_assignment_does_not_claim_execution(self):
        report = audit(self.root)
        self.assertEqual(report['counts'], dict(primitives=102, scenarios=37, steps=297))
        self.assertEqual(report['contract_audit'], 'PASS')
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
        self.assertTrue(all(s['status'] == 'NOT_RUN' for s in report['stages']))
        self.assertTrue(all(c['evidence'] == 'SOURCE_REVIEW_ONLY' for c in report['reviewed_cores'].values()))

    def test_rejects_omission_duplication_reordering_and_promotion(self):
        def change(name, c):
            if name == 'missing': c['stages'][2]['scenarios'].pop()
            if name == 'duplicate': c['stages'][3]['scenarios'].append(c['stages'][2]['scenarios'][0])
            if name == 'unknown': c['stages'][0]['scenarios'].append('guard-invented')
            if name == 'primitive': c['stages'][0]['primitive_cases'].pop()
            if name == 'order': c['stages'].reverse()
            if name == 'prerequisite': c['stages'][3]['requires'].pop()
            if name == 'promote': c['stages'][0]['binding_status'] = 'PASS'
            if name == 'conformance': c['conformance'] = 'PASS'
            if name == 'runtime': c['reviewed_cores']['go']['evidence'] = 'RUNTIME_PASS'
            if name == 'source': c['sources'][SPEC] = '0' * 64
            if name == 'extra': c['approval'] = True
            if name == 'version': c['schema_version'] = True
        for name in ('missing', 'duplicate', 'unknown', 'primitive', 'order', 'prerequisite', 'promote', 'conformance', 'runtime', 'source', 'extra', 'version'):
            with self.subTest(name=name):
                c = copy.deepcopy(self.contract)
                change(name, c)
                (self.root / CONTRACT).write_text(json.dumps(c))
                with self.assertRaises(ValueError):
                    audit(self.root)

    def test_frozen_fixture_change_is_not_accepted(self):
        fixture = next((self.root / 'vectors/0.10.0/guard-scenarios').glob('*.json'))
        fixture.write_bytes(fixture.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'scenario hash mismatch'):
            audit(self.root)

    def test_duplicate_json_members_rejected(self):
        p = self.root / CONTRACT
        p.write_text(p.read_text().replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            audit(self.root)

    def test_cli_incomplete_and_existing_output_preserved(self):
        output = self.root / 'results'
        command = [sys.executable, str(ROOT / 'scripts/inspect_guard_binding.py'), '--output', str(output)]
        p = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 3, p.stderr)
        raw = (output / 'report.json').read_bytes()
        self.assertEqual(json.loads(raw), audit())
        p = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertEqual((output / 'report.json').read_bytes(), raw)

    def test_cli_rejects_bad_contract_and_historical_destination(self):
        shutil.copytree(ROOT / 'scripts', self.root / 'scripts', ignore=shutil.ignore_patterns('__pycache__'))
        command = [sys.executable, str(self.root / 'scripts/inspect_guard_binding.py')]
        self.contract['conformance'] = 'PASS'
        (self.root / CONTRACT).write_text(json.dumps(self.contract))
        p = subprocess.run(command + ['--output', str(self.root / 'invalid')], capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertFalse((self.root / 'invalid').exists())
        p = subprocess.run(command + ['--output', str(self.root / 'docs/evidence/new')], capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertFalse((self.root / 'docs/evidence/new').exists())


if __name__ == '__main__':
    unittest.main()
