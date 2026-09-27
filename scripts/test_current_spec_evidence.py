"""Controls for current-revision case evidence admission and status derivation."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import current_spec_evidence as checker


class CurrentSpecEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'inspector'
        self.evidence = Path(self.temporary.name) / 'evidence'
        self.evidence.mkdir()
        base = self.root / 'verification/0.10.0'
        current = base / 'current-spec'
        current.mkdir(parents=True)
        for name in ('manifest.json', 'traceability.json', 'additional-case-map.json',
                     'bindings.json'):
            shutil.copy2(checker.ROOT / 'verification/0.10.0/current-spec' / name,
                         current / name)
        binding_contract = json.loads((current / 'bindings.json').read_text())
        binding_contract['bindings'] = []
        (current / 'bindings.json').write_text(json.dumps(binding_contract))
        shutil.copy2(checker.ROOT / 'verification/0.10.0/case-map.json',
                     base / 'case-map.json')
        self.revision = json.loads((current / 'manifest.json').read_text())['spec_revision']
        self.subject = {'repository': 'example/core', 'revision': 'a' * 40,
                        'executable_sha256': 'b' * 64}

    def bind(self, ident='merrata-config-valid', track='runtime', coverage='complete'):
        fixture = {'schema_version': 1, 'spec_revision': self.revision,
                   'id': ident, 'track': track,
                   'input': {'operation': 'synthetic-safe-check'},
                   'expected': {'verdict': 'ACCEPT', 'output': {'accepted': True},
                                'effects': {'dispatch': 0}}}
        path = f'vectors/0.10.0/current-spec/{ident}.json'
        full = self.root / path
        full.parent.mkdir(parents=True, exist_ok=True)
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        full.write_bytes(raw)
        row = {'id': ident, 'track': track, 'fixture': path,
               'fixture_sha256': checker.sha(raw), 'coverage': coverage}
        contract_path = self.root / 'verification/0.10.0/current-spec/bindings.json'
        contract = json.loads(contract_path.read_text())
        contract['bindings'].append(row)
        contract_path.write_text(json.dumps(contract))
        return row, fixture

    def observe(self, row, fixture, actual=None):
        actual = actual or fixture['expected']
        record = {'schema_version': 1, 'spec_revision': self.revision,
                  'id': row['id'], 'track': row['track'],
                  'fixture_sha256': row['fixture_sha256'],
                  'input_sha256': checker.sha(json.dumps(
                      fixture['input'], sort_keys=True, separators=(',', ':')).encode()),
                  'subject': self.subject, 'actual': actual,
                  'environment': 'bounded-local-test'}
        name = row['id'] + '.json'
        raw = (json.dumps(record, indent=2) + '\n').encode()
        (self.evidence / name).write_bytes(raw)
        manifest = {'schema_version': 1, 'spec_revision': self.revision,
                    'subject': self.subject, 'runner_revision': 'c' * 40,
                    'runner_sha256': 'e' * 64,
                    'adapter_sha256': 'd' * 64,
                    'observations': [{'id': row['id'], 'track': row['track'],
                                      'path': name, 'sha256': checker.sha(raw)}]}
        (self.evidence / 'manifest.json').write_text(json.dumps(manifest))

    def result(self, ident, evidence=True):
        report = checker.assess(self.root, self.evidence if evidence else None)
        return next(row for row in report['cases'] if row['id'] == ident), report

    def test_empty_bindings_cannot_promote_any_case_or_child(self):
        row, report = self.result('merrata-config-valid', evidence=False)
        self.assertEqual(row['status'], 'NOT_RUN')
        self.assertEqual(report['counts']['NOT_RUN'], 481)
        self.assertEqual(len(report['mandatory_subscenarios']), 26)
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')

    def test_complete_partial_failure_and_unsupported_are_distinct(self):
        row, fixture = self.bind()
        self.observe(row, fixture)
        case, report = self.result(row['id'])
        self.assertEqual(case['status'], 'PASS')
        self.assertEqual(report['counts']['PASS'], 1)
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
        contract_path = self.root / 'verification/0.10.0/current-spec/bindings.json'
        contract = json.loads(contract_path.read_text())
        contract['bindings'][0]['coverage'] = 'partial'
        contract_path.write_text(json.dumps(contract))
        self.assertEqual(self.result(row['id'])[0]['status'], 'PARTIAL')
        self.observe(row, fixture, {'verdict': 'REJECT', 'output': {'accepted': False},
                                    'effects': {'dispatch': 0}})
        self.assertEqual(self.result(row['id'])[0]['status'], 'FAIL')
        self.observe(row, fixture, {'verdict': 'UNSUPPORTED', 'reason': 'No adapter binding'})
        self.assertEqual(self.result(row['id'])[0]['status'], 'UNSUPPORTED')

    def test_missing_mandatory_children_prevent_parent_pass(self):
        row, fixture = self.bind('madd-close-before-handoff')
        self.observe(row, fixture)
        case, report = self.result(row['id'])
        self.assertEqual(case['tracks'], {'runtime': 'PASS'})
        self.assertEqual(case['status'], 'PARTIAL')
        self.assertTrue(any(child['parent_case'] == row['id'] and child['status'] == 'NOT_RUN'
                            for child in report['mandatory_subscenarios']))

    def test_tampered_observation_and_wrong_spec_are_rejected(self):
        row, fixture = self.bind()
        self.observe(row, fixture)
        (self.evidence / (row['id'] + '.json')).write_text('{}')
        with self.assertRaisesRegex(ValueError, 'observation hash'):
            checker.assess(self.root, self.evidence)
        self.observe(row, fixture)
        manifest_path = self.evidence / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['spec_revision'] = '0' * 40
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'observation manifest identity'):
            checker.assess(self.root, self.evidence)

    def test_cli_report_is_incomplete_without_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'report.json'
            proc = subprocess.run([sys.executable, '-B', str(checker.ROOT / 'scripts/current_spec_evidence.py'),
                                   '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(output.read_text())['counts']['NOT_RUN'], 481)


if __name__ == '__main__':
    unittest.main()
