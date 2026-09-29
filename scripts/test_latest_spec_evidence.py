"""Latest-case evidence cannot inherit or overstate earlier observations."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import latest_spec_evidence as checker
from latest_spec_case_bindings import BINDINGS, VECTOR_BASE
from current_spec_catalog import sha


class LatestSpecEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'inspector'
        self.evidence = Path(self.temporary.name) / 'evidence'
        self.evidence.mkdir()
        for relative in ('verification/0.10.0/case-map.json', BINDINGS):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(checker.ROOT / relative, target)
        for name in ('manifest.json', 'traceability.json', 'additional-case-map.json'):
            relative = checker.LATEST_BASE + '/' + name
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(checker.ROOT / relative, target)
        for source in (checker.ROOT / VECTOR_BASE).glob('*.json'):
            target = self.root / VECTOR_BASE / source.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        self.subject = {'repository': 'example/observer', 'revision': 'a' * 40,
                        'executable_sha256': 'b' * 64}

    def observe(self, revision=checker.LATEST_REVISION, actual=None):
        binding = json.loads((self.root / BINDINGS).read_bytes())['bindings'][0]
        fixture = json.loads((self.root / binding['fixture']).read_bytes())
        result = {'schema_version': 1, 'spec_revision': revision,
                  'id': binding['id'], 'track': 'runtime',
                  'fixture_sha256': binding['fixture_sha256'],
                  'input_sha256': sha(json.dumps(
                      fixture['input'], sort_keys=True, separators=(',', ':')).encode()),
                  'subject': self.subject,
                  'actual': actual or fixture['expected'],
                  'environment': 'synthetic-unit-test'}
        raw = (json.dumps(result, indent=2) + '\n').encode()
        (self.evidence / 'observation.json').write_bytes(raw)
        manifest = {'schema_version': 1, 'spec_revision': revision,
                    'subject': self.subject, 'runner_revision': 'c' * 40,
                    'runner_sha256': 'd' * 64, 'adapter_sha256': 'e' * 64,
                    'observations': [{'id': binding['id'], 'track': 'runtime',
                                      'path': 'observation.json', 'sha256': sha(raw)}]}
        (self.evidence / 'manifest.json').write_text(json.dumps(manifest))
        return binding['id']

    def test_unobserved_latest_cases_remain_not_run(self):
        report = checker.assess(self.root)
        self.assertEqual(report['counts']['NOT_RUN'], 489)
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
        self.assertEqual(len(report['mandatory_subscenarios']), 26)

    def test_matching_synthetic_observation_is_only_partial(self):
        ident = self.observe()
        report = checker.assess(self.root, self.evidence)
        row = next(row for row in report['cases'] if row['id'] == ident)
        self.assertEqual(row['status'], 'PARTIAL')
        self.assertEqual(report['counts']['PASS'], 0)
        self.assertEqual(report['counts']['NOT_RUN'], 488)

    def test_earlier_revision_observation_is_rejected(self):
        self.observe(revision='5bcf511e604579afa63f434013447f44b6858828')
        with self.assertRaisesRegex(ValueError, 'observation manifest identity'):
            checker.assess(self.root, self.evidence)

    def test_missing_bound_fixture_fails_closed(self):
        path = self.root / VECTOR_BASE / 'msca-http-ed25519.json'
        path.unlink()
        with self.assertRaises(OSError):
            checker.assess(self.root)

    def test_bounded_cli_keeps_all_cases_unobserved(self):
        output = Path(self.temporary.name) / 'report.json'
        result = subprocess.run([
            sys.executable, '-B', str(checker.ROOT / 'scripts/latest_spec_evidence.py'),
            '--output', str(output)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_bytes())['counts']['NOT_RUN'], 489)


if __name__ == '__main__':
    unittest.main()
