"""The design-baseline runner must bind outcomes to frozen contracts only."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from current_spec_catalog import ROOT, load, sha
from design_baseline_evidence import assess
import run_design_baseline_cases as runner

CASES = ['JCS-01-N01', 'JCS-01-P', 'HPKE-03-P']


class DesignBaselineRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.subject = self.base / 'core-adapter'
        self.subject.write_bytes(b'pinned core adapter build\n')
        self.output = self.base / 'out'

    def bridge(self, outcomes):
        # Fake bridge: asserts the 0.10.0 profile and answers per case.
        path = self.base / 'bridge.py'
        path.write_text(
            '#!/usr/bin/env python3\nimport json,os,sys\n'
            "assert os.environ['SAGE_CORE_PROFILE']=='primitive-foundation-010'\n"
            'request=json.load(sys.stdin)\n'
            "assert 'expected' not in request\n"
            'outcomes=' + json.dumps(outcomes) + '\n'
            "print(json.dumps({'schema_version':1,'id':request['id'],"
            "'track':'runtime','actual':outcomes[request['id']]}))\n")
        path.chmod(0o755)
        return path

    def run_cases(self, outcomes, cases=CASES, **kwargs):
        env = {'SAGE_CORE_ADAPTER': str(self.subject)}
        with mock.patch.dict(os.environ, env):
            return runner.run(ROOT, self.bridge(outcomes), 'SAGE-X-project/sage',
                              'a' * 40, self.subject, self.output, selected=cases,
                              runner_revision='c' * 40, **kwargs)

    def test_matching_outcomes_stay_partial_and_carry_observer_facts(self):
        expected = {'JCS-01-N01': {'verdict': 'REJECT', 'output': {}, 'effects': {}},
                    'JCS-01-P': {'verdict': 'UNSUPPORTED', 'reason': 'not exposed'},
                    'HPKE-03-P': {'verdict': 'REJECT', 'output': {}, 'effects': {}}}
        manifest = self.run_cases(expected)
        self.assertEqual([row['id'] for row in manifest['observations']], sorted(CASES))
        self.assertEqual(manifest['artifacts'][0]['path'],
                         'runner/run_design_baseline_cases.py')
        observation = load((self.output / 'JCS-01-N01-runtime.json').read_bytes())
        self.assertEqual(observation['environment'], 'local-process')
        self.assertEqual(observation['facts']['independent_observer'],
                         {'repository': 'SAGE-X-project/sage-inspector',
                          'revision': 'c' * 40,
                          'artifact_sha256': manifest['runner_sha256']})
        self.assertEqual(observation['subject']['executable_sha256'],
                         sha(self.subject.read_bytes()))
        unsupported = load((self.output / 'JCS-01-P-runtime.json').read_bytes())
        self.assertEqual(unsupported['facts'], {})
        report = assess(ROOT, self.output)
        status = {(row['id'], row['track']): row['status'] for row in report['tracks']}
        self.assertEqual(status['JCS-01-N01', 'runtime'], 'PARTIAL')
        self.assertEqual(status['JCS-01-P', 'runtime'], 'UNSUPPORTED')
        self.assertEqual(status['HPKE-03-P', 'runtime'], 'FAIL')
        self.assertEqual(report['counts']['PASS'], 0)

    def test_host_case_fixtures_are_not_selected(self):
        with self.assertRaisesRegex(ValueError, 'one or more selected cases'):
            self.run_cases({}, cases=['CRYPTO-01-N01'])

    def test_unpinned_subject_adapter_is_refused(self):
        other = self.base / 'other-adapter'
        other.write_bytes(b'different build\n')
        with mock.patch.dict(os.environ, {'SAGE_CORE_ADAPTER': str(other)}):
            with self.assertRaisesRegex(ValueError, 'differs from pinned executable'):
                runner.run(ROOT, self.bridge({}), 'SAGE-X-project/sage', 'a' * 40,
                           self.subject, self.output, selected=CASES[:1],
                           runner_revision='c' * 40)

    def test_output_inside_repository_is_refused(self):
        self.output = ROOT / 'design-baseline-output-must-not-exist'
        with self.assertRaisesRegex(ValueError, 'outside repository'):
            self.run_cases({}, cases=CASES[:1])
        self.assertFalse(self.output.exists())

    def test_observer_cannot_be_its_own_subject(self):
        with mock.patch.dict(os.environ, {'SAGE_CORE_ADAPTER': str(self.subject)}):
            with self.assertRaisesRegex(ValueError, 'subject repository'):
                runner.run(ROOT, self.bridge({}), runner.OBSERVER, 'a' * 40,
                           self.subject, self.output, selected=CASES[:1],
                           runner_revision='c' * 40)


if __name__ == '__main__':
    unittest.main()
