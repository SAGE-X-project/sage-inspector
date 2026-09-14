"""Tampering and coverage regression checks; no subject implementation required."""
import contextlib
import copy
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import integrate_evidence as audit

ROOT = Path(__file__).resolve().parents[1]
CATALOG = 'verification/0.10.0/evidence-catalog.json'


class IntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        for directory in ('verification', 'vectors', 'docs/evidence'):
            shutil.copytree(ROOT / directory, cls.root / directory)
        cls.catalog = json.loads((cls.root / CATALOG).read_text())
        with contextlib.redirect_stdout(io.StringIO()):
            cls.report = audit.build(cls.root, cls.root / CATALOG)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def mutate(self, change, path=None, repin=True):
        catalog = copy.deepcopy(self.catalog)
        file = self.root / path if path else None
        original = file.read_bytes() if file else None
        try:
            if file:
                data = json.loads(original)
                change(data)
                file.write_text(json.dumps(data))
                if repin:
                    catalog['files'][path] = audit.sha(file.read_bytes())
            else:
                change(catalog)
            (self.root / CATALOG).write_text(json.dumps(catalog))
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises((ValueError, KeyError, AssertionError)):
                audit.build(self.root, self.root / CATALOG)
        finally:
            if file:
                file.write_bytes(original)
            (self.root / CATALOG).write_text(json.dumps(self.catalog))

    def test_counts_and_no_certification(self):
        for core, expected in [('go', (145, 69, 311)), ('rust', (159, 63, 303))]:
            report = self.report['cores'][core]
            self.assertEqual(report['primitive_counts'], dict(zip(audit.STATUSES, (*expected, 0))))
            self.assertEqual(report['scenario_counts'], {'NOT_RUN': 97})
            self.assertEqual(report['scenario_steps'], 648)
            self.assertEqual(report['planned_case_counts']['NOT_RUN'], 386)
            self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
            self.assertEqual(sum(o['coverage'] == 'conditional' for o in report['observations']), 6)
            self.assertTrue(all(r['conformance'] == 'NOT_ESTABLISHED' for r in report['requirements']))
            self.assertTrue(all(s['observed_effects'] is None for s in report['scenarios']))
            self.assertEqual(len(report['runs']), 10)
            self.assertGreater(len({r['subject']['executable_sha256'] for r in report['runs']}), 1)

    def test_missing_suite(self):
        self.mutate(lambda c: c['cores'][0]['reports'].pop())

    def test_duplicate_suite(self):
        self.mutate(lambda c: c['cores'][0]['reports'].append(c['cores'][0]['reports'][0]))

    def test_missing_scenario(self):
        self.mutate(lambda c: c['scenarios'].pop())

    def test_path_escape(self):
        self.mutate(lambda c: c['files'].update({'../../escaped.json': '0' * 64}))

    def test_changed_bytes(self):
        self.mutate(lambda r: r.update(environment='fake'), 'docs/evidence/core-go.json', repin=False)

    def test_false_pass(self):
        def change(r):
            result = next(x for x in r['results'] if x['status'] == 'UNSUPPORTED')
            result['status'] = 'PASS'
            r['counts']['UNSUPPORTED'] -= 1
            r['counts']['PASS'] += 1
        self.mutate(change, 'docs/evidence/core-go.json')

    def test_wrong_subject(self):
        self.mutate(lambda r: r['subject'].update(revision='0' * 40), 'docs/evidence/core-go.json')

    def test_reference_not_core(self):
        self.mutate(lambda r: r['subject'].update(kind='reference'), 'docs/evidence/core-go.json')

    def test_missing_environment(self):
        self.mutate(lambda r: r.pop('environment'), 'docs/evidence/core-go.json')

    def test_duplicate_result(self):
        self.mutate(lambda r: r['results'].append(r['results'][0]), 'docs/evidence/core-go.json')

    def test_missing_result(self):
        self.mutate(lambda r: r['results'].pop(), 'docs/evidence/core-go.json')

    def test_unbacked_scenario_pass(self):
        self.mutate(lambda c: c['cores'][0]['scenario_reports'].update({c['scenarios'][0]['id']: 'docs/evidence/core-go.json'}))

    def test_stateful_effect_ingestion(self):
        catalog = copy.deepcopy(self.catalog)
        entry = next(e for e in catalog['scenarios'] if e['id'] == 'guard-pending-completed')
        raw = (self.root / entry['fixture']).read_bytes()
        fixture = json.loads(raw)
        core = catalog['cores'][0]
        report = dict(schema_version=2, protocol_version='0.10.0', profile='stateful-scenario',
                      fixture_sha256=audit.sha(raw), case_id=fixture['id'], status='PASS', steps=[],
                      sources=fixture['sources'], environment='synthetic test only', created='2026-09-14T00:00:00Z',
                      subject=dict(name=core['subject_names'][0], revision=core['revision'],
                                   kind='external', executable_sha256='a' * 64))
        for step in fixture['steps']:
            report['steps'].append(dict(step_id=step['id'], input=step['input'], expected=step['expected'],
                expected_effects=step['effects'], status='PASS', actual=dict(schema_version=2,
                case_id=fixture['id'], step_id=step['id'], **step['expected'], effects=step['effects'])))
        path = 'docs/evidence/synthetic-state.json'
        catalog['cores'][0]['scenario_reports'][fixture['id']] = path
        try:
            for corrupt in (False, True):
                data = copy.deepcopy(report)
                if corrupt:
                    data['steps'][1]['actual']['effects']['dispatch'] += 1
                (self.root / path).write_text(json.dumps(data))
                catalog['files'][path] = audit.sha((self.root / path).read_bytes())
                (self.root / CATALOG).write_text(json.dumps(catalog))
                with contextlib.redirect_stdout(io.StringIO()):
                    if corrupt:
                        with self.assertRaises(ValueError):
                            audit.build(self.root, self.root / CATALOG)
                    else:
                        result = audit.build(self.root, self.root / CATALOG)['cores']['go']
                        observed = next(s for s in result['scenarios'] if s['id'] == fixture['id'])
                        self.assertEqual(observed['observed_effects'][1]['effects'], fixture['steps'][1]['effects'])
                        self.assertEqual(result['conformance'], 'NOT_ESTABLISHED')
                        self.assertEqual(result['planned_case_counts']['NOT_RUN'], 386)
        finally:
            (self.root / path).unlink(missing_ok=True)
            (self.root / CATALOG).write_text(json.dumps(self.catalog))

    def test_cli_exit_and_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'report.json'
            command = [sys.executable, str(ROOT / 'scripts/integrate_evidence.py'),
                       '--root', str(self.root), '--output', str(output)]
            def run(*args):
                return subprocess.run(command + list(args), capture_output=True, timeout=15).returncode
            self.assertEqual(run(), 0)
            original = output.read_bytes()
            self.assertEqual(run(), 2)
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(run('--check'), 0)
            self.assertEqual(run('--check', '--require-conformance'), 3)
            output.write_text('{}')
            self.assertEqual(run('--check'), 2)

    def test_strict_json(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}'):
            with self.assertRaises(ValueError):
                audit.decode(raw)
        self.assertFalse(audit.same({'value': True}, {'value': 1}))


if __name__ == '__main__':
    unittest.main()
