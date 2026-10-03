"""Exercise revision, observer, and outcome guards on the frozen catalog."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from current_spec_catalog import sha
from design_baseline_catalog import SPEC_REVISION, verify as verify_catalog
from design_baseline_evidence import assess


class DesignBaselineEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence = Path(self.temp.name)
        _, _, source = verify_catalog()
        self.row = next(row for row in source['contracts']
                        if row['id'] == 'JCS-01-P' and row['track'] == 'runtime')
        self.full = next(row for row in source['contracts']
                         if row['id'] == 'full-case/JCS-01-P' and
                         row['track'] == 'runtime')
        self.subject = {'repository': 'SAGE-X-project/sage',
                        'revision': 'a' * 40, 'executable_sha256': 'b' * 64}
        artifact = b'independent bounded observation\n'
        (self.evidence / 'observer.txt').write_bytes(artifact)
        self.artifact_sha256 = sha(artifact)
        self.observer = {'repository': 'SAGE-X-project/sage-inspector',
                         'revision': 'c' * 40,
                         'artifact_sha256': self.artifact_sha256}

    def write_observation(self, actual=None, revision=SPEC_REVISION,
                          omit_fact=None):
        actual = copy.deepcopy(actual or self.row['expected'])
        facts = {
            'subject_revision': self.subject['revision'],
            'executable_sha256': self.subject['executable_sha256'],
            'input_sha256': self.row['input_sha256'],
            'actual_verdict': actual['verdict'],
            'actual_output': actual['output'],
            'effect_counts': actual['effects'],
            'independent_observer': self.observer,
        }
        if omit_fact:
            del facts[omit_fact]
        observation = {'schema_version': 1, 'spec_revision': revision,
                       'id': self.row['id'], 'track': 'runtime',
                       'source_fixture_sha256': self.row['source_fixture_sha256'],
                       'subject': self.subject, 'actual': actual,
                       'facts': facts, 'environment': 'local-process'}
        raw = (json.dumps(observation) + '\n').encode()
        (self.evidence / 'observation.json').write_bytes(raw)
        manifest = {'schema_version': 1, 'protocol_version': '0.10.0',
                    'profiles': ['base'],
                    'spec_revision': revision, 'subject': self.subject,
                    'runner_revision': 'e' * 40, 'runner_sha256': 'f' * 64,
                    'adapter_sha256': '0' * 64,
                    'artifacts': [{'path': 'observer.txt',
                                   'sha256': self.artifact_sha256}],
                    'observations': [{'id': self.row['id'], 'track': 'runtime',
                                      'path': 'observation.json', 'sha256': sha(raw)}]}
        (self.evidence / 'manifest.json').write_text(json.dumps(manifest))

    def add_full_observation(self, supporting=True):
        manifest_path = self.evidence / 'manifest.json'
        manifest = json.loads(manifest_path.read_bytes())
        if not supporting:
            manifest['observations'] = []
        actual = self.full['expected']
        facts = {
            'subject_revision': self.subject['revision'],
            'executable_sha256': self.subject['executable_sha256'],
            'input_sha256': self.full['input_sha256'],
            'actual_verdict': actual['verdict'],
            'actual_output': actual['output'],
            'effect_counts': actual['effects'],
            'independent_observer': self.observer,
            'clause_findings': {
                ident: {'status': 'MATCH',
                        'evidence_sha256': self.artifact_sha256}
                for ident in self.full['required_clause_ids']},
            'effect_evidence_sha256': self.artifact_sha256,
        }
        observation = {'schema_version': 1, 'spec_revision': SPEC_REVISION,
                       'id': self.full['id'], 'track': 'runtime',
                       'source_fixture_sha256': self.full['source_fixture_sha256'],
                       'subject': self.subject, 'actual': actual,
                       'facts': facts, 'environment': 'local-process'}
        raw = (json.dumps(observation) + '\n').encode()
        (self.evidence / 'full.json').write_bytes(raw)
        manifest['observations'].append({'id': self.full['id'], 'track': 'runtime',
                                         'path': 'full.json', 'sha256': sha(raw)})
        manifest_path.write_text(json.dumps(manifest))

    def test_empty_run_remains_not_run(self):
        result = assess()
        self.assertEqual(result['counts']['NOT_RUN'], 489)
        self.assertEqual(result['required_subcondition_count'], 56)
        self.assertEqual(result['conformance'], 'NOT_ESTABLISHED')

    def test_matching_prior_fixture_is_partial_only(self):
        self.write_observation()
        result = assess(evidence_root=self.evidence)
        self.assertEqual(result['counts']['PARTIAL'], 1)
        self.assertEqual(result['counts']['PASS'], 0)
        self.assertEqual(result['counts']['NOT_RUN'], 488)

    def test_mismatch_is_fail(self):
        actual = copy.deepcopy(self.row['expected'])
        actual['output']['canonical_hex'] = '00'
        self.write_observation(actual)
        self.assertEqual(assess(evidence_root=self.evidence)['counts']['FAIL'], 1)

    def test_old_revision_is_rejected(self):
        self.write_observation(revision='44df132fee5925182018ce089dc82435cb353f8a')
        with self.assertRaisesRegex(ValueError, 'observation manifest identity'):
            assess(evidence_root=self.evidence)

    def test_missing_observer_fact_is_rejected(self):
        self.write_observation(omit_fact='independent_observer')
        with self.assertRaisesRegex(ValueError, 'observation facts'):
            assess(evidence_root=self.evidence)

    def test_full_clause_evidence_requires_local_fixture(self):
        self.write_observation()
        self.add_full_observation(supporting=False)
        result = assess(evidence_root=self.evidence)
        self.assertEqual(result['counts']['PARTIAL'], 1)
        self.assertEqual(result['counts']['PASS'], 0)

    def test_full_clause_and_local_fixture_can_complete_a_case(self):
        self.write_observation()
        self.add_full_observation()
        result = assess(evidence_root=self.evidence)
        self.assertEqual(result['counts']['PASS'], 1)
        self.assertEqual(result['counts']['NOT_RUN'], 488)

    def test_missing_artifact_is_rejected(self):
        self.write_observation()
        (self.evidence / 'observer.txt').unlink()
        with self.assertRaises(OSError):
            assess(evidence_root=self.evidence)

    def test_unit_simulation_cannot_pass_full_case(self):
        self.write_observation()
        self.add_full_observation()
        path = self.evidence / 'full.json'
        observation = json.loads(path.read_bytes())
        observation['environment'] = 'unit-simulation'
        raw = (json.dumps(observation) + '\n').encode()
        path.write_bytes(raw)
        manifest_path = self.evidence / 'manifest.json'
        manifest = json.loads(manifest_path.read_bytes())
        manifest['observations'][-1]['sha256'] = sha(raw)
        manifest_path.write_text(json.dumps(manifest))
        self.assertEqual(assess(evidence_root=self.evidence)['counts']['PARTIAL'], 1)

if __name__ == '__main__':
    unittest.main()
