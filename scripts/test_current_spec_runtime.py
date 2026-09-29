"""Bounded local adapter execution for current-spec case fixtures."""

import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import current_spec_evidence as evidence
import run_current_spec_cases as runner


class CurrentSpecRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'inspector'
        base = self.root / 'verification/0.10.0'
        current = base / 'current-spec'
        current.mkdir(parents=True)
        for name in ('manifest.json', 'traceability.json', 'additional-case-map.json',
                     'bindings.json'):
            shutil.copy2(runner.ROOT / 'verification/0.10.0/current-spec' / name,
                         current / name)
        binding_contract = json.loads((current / 'bindings.json').read_text())
        binding_contract['bindings'] = []
        (current / 'bindings.json').write_text(json.dumps(binding_contract))
        shutil.copy2(runner.ROOT / 'verification/0.10.0/case-map.json',
                     base / 'case-map.json')
        self.spec_revision = json.loads((current / 'manifest.json').read_text())['spec_revision']
        self.output = Path(self.temporary.name) / 'evidence'
        self.adapter = Path(self.temporary.name) / 'adapter.py'

    def bind(self):
        fixture = {'schema_version': 1, 'spec_revision': self.spec_revision,
                   'id': 'merrata-config-valid', 'track': 'runtime',
                   'input': {'operation': 'inert'},
                   'expected': {'verdict': 'ACCEPT', 'output': {'ok': True},
                                'effects': {'dispatch': 0}}}
        path = self.root / 'vectors/0.10.0/current-spec/merrata-config-valid.json'
        path.parent.mkdir(parents=True)
        raw = (json.dumps(fixture) + '\n').encode()
        path.write_bytes(raw)
        contract_path = self.root / 'verification/0.10.0/current-spec/bindings.json'
        contract = json.loads(contract_path.read_text())
        contract['bindings'] = [{'id': fixture['id'], 'track': fixture['track'],
                                 'fixture': 'vectors/0.10.0/current-spec/merrata-config-valid.json',
                                 'fixture_sha256': runner.sha(raw), 'coverage': 'complete'}]
        contract_path.write_text(json.dumps(contract))

    def make_adapter(self, outcome=None, wrong_id=False):
        outcome = outcome or {'verdict': 'ACCEPT', 'output': {'ok': True},
                              'effects': {'dispatch': 0}}
        program = ('#!/usr/bin/env python3\nimport json,sys\n'
                   'request=json.load(sys.stdin)\n'
                   "assert 'expected' not in request\n"
                   'print(json.dumps({"schema_version":1,"id":'
                   + ('"wrong"' if wrong_id else 'request["id"]') +
                   ',"track":request["track"],"actual":' + repr(outcome) + '}))\n')
        self.adapter.write_text(program)
        self.adapter.chmod(0o755)

    def test_safe_runtime_capture_and_independent_evaluation(self):
        self.bind()
        self.make_adapter()
        report = runner.run(self.root, self.adapter, 'example/core', 'a' * 40,
                            self.output, selected='merrata-config-valid',
                            runner_revision='c' * 40)
        self.assertEqual(len(report['observations']), 1)
        assessed = evidence.assess(self.root, self.output)
        self.assertEqual(assessed['counts']['PASS'], 1)
        self.assertEqual(assessed['counts']['NOT_RUN'], 480)
        self.assertEqual(assessed['conformance'], 'NOT_ESTABLISHED')

    def test_wrong_adapter_identity_does_not_create_usable_manifest(self):
        self.bind()
        self.make_adapter(wrong_id=True)
        with self.assertRaisesRegex(ValueError, 'adapter response identity'):
            runner.run(self.root, self.adapter, 'example/core', 'a' * 40,
                       self.output, runner_revision='c' * 40)
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_multi_case_selection_rejects_unbound_id(self):
        self.bind()
        self.make_adapter()
        with self.assertRaisesRegex(ValueError, 'one or more selected cases'):
            runner.run(self.root, self.adapter, 'example/core', 'a' * 40,
                       self.output, selected=['merrata-config-valid', 'unknown'],
                       runner_revision='c' * 40)
        self.assertFalse(self.output.exists())

    def test_missing_fixture_is_not_silently_skipped(self):
        self.make_adapter()
        with self.assertRaisesRegex(ValueError, 'no runtime fixture'):
            runner.run(self.root, self.adapter, 'example/core', 'a' * 40,
                       self.output, runner_revision='c' * 40)

    def test_configured_host_must_match_pinned_subject(self):
        self.bind()
        self.make_adapter()
        with patch.dict('os.environ', {'SAGE_CASE_ADAPTER': str(self.adapter)}):
            with self.assertRaisesRegex(ValueError, 'needs a pinned executable'):
                runner.run(self.root, self.adapter, 'example/core', 'a' * 40,
                           self.output, runner_revision='c' * 40)
            other = Path(self.temporary.name) / 'other-adapter'
            other.write_bytes(self.adapter.read_bytes())
            with self.assertRaisesRegex(ValueError, 'differs from pinned executable'):
                runner.run(self.root, self.adapter, 'example/core', 'a' * 40,
                           self.output, subject_executable=other,
                           runner_revision='c' * 40)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
