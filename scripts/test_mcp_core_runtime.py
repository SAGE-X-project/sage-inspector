"""Evidence classifier controls and harmless bounded process runtime tests."""
import copy
from pathlib import Path
import sys
import json
import subprocess
import tempfile
import unittest
from run_mcp_core_runtime import (CASES, OWNER_CONTRACT, OWNER_CONTRACT_CASES,
                                  SIGNATURE_CONTRACT, SIGNATURE_CONTRACT_CASES,
                                  SCHEDULES, ROOT, digest, observed, run, successful)


class EvidenceTests(unittest.TestCase):
    def test_schedule_selection_is_complete_and_unique(self):
        self.assertEqual(set(SCHEDULES), {'go','rust'})
        for language, claims in SCHEDULES.items():
            self.assertEqual(len(claims),4)
            self.assertEqual(len(OWNER_CONTRACT_CASES[language]), 13)
            self.assertEqual(len(CASES[language]),24)
            self.assertEqual(len(set(CASES[language])),24)
            self.assertTrue(all(name in CASES[language] and claim for name,claim in claims.items()))
            covered = set().union(*map(set, OWNER_CONTRACT_CASES[language].values()))
            self.assertEqual(covered, {'durable-admission', 'close-linearization',
                                       'owner-isolation', 'output-publication',
                                       'ready-past-setup', 'stale-setup-completion',
                                       'close-before-reservation'})

    def test_owner_contract_is_bound_to_runtime_runner(self):
        self.assertEqual(len(digest(OWNER_CONTRACT)), 64)
        for language, cases in OWNER_CONTRACT_CASES.items():
            self.assertTrue(all(name in CASES[language] and boundaries
                                for name, boundaries in cases.items()))
        self.assertEqual(len(digest(SIGNATURE_CONTRACT)), 64)
        for language, cases in SIGNATURE_CONTRACT_CASES.items():
            self.assertEqual(len(cases), 4)
            self.assertTrue(all(name in CASES[language] for name in cases))

    def test_go_requires_exact_execution(self):
        text = '=== RUN   Sample\n--- PASS: Sample (0.01s)\nPASS\n'
        self.assertTrue(observed('go', 'Sample', text, 0))
        children = ('=== RUN   Sample\n=== RUN   Sample/one\n'
                    '    --- PASS: Sample/one (0.00s)\n--- PASS: Sample (0.01s)\nPASS\n')
        self.assertTrue(observed('go', 'Sample', children, 0))
        for bad in ('PASS\n', text.replace('Sample', 'Other'),
                    text.replace('PASS:', 'SKIP:'), text + text,
                    children.replace('Sample/one', 'Other/one', 1),
                    children.replace('PASS: Sample/one', 'FAIL: Sample/one')):
            self.assertFalse(observed('go', 'Sample', bad, 0))
        self.assertFalse(observed('go', 'Sample', text, 1))

    def test_rust_requires_one_pass_no_skips(self):
        text = 'test Sample ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 99 filtered out;\n'
        self.assertTrue(observed('rust', 'Sample', text, 0))
        for bad in (text.replace('1 passed', '0 passed'), text.replace('0 ignored', '1 ignored'),
                    text.replace('Sample', 'Other'), text + text, 'test Sample ... ok\n'):
            self.assertFalse(observed('rust', 'Sample', bad, 0))
        self.assertFalse(observed('rust', 'Sample', text, -9))

    def test_report_requires_all_pinned_tests(self):
        subjects = {lang: dict(build=dict(status='PASS'), cases=[dict(
                    test=name, status='PASS',
                    **({'owner_admission_boundaries': OWNER_CONTRACT_CASES[lang][name]}
                       if name in OWNER_CONTRACT_CASES[lang] else {}),
                    **({'signature_boundary': SIGNATURE_CONTRACT_CASES[lang][name]}
                       if name in SIGNATURE_CONTRACT_CASES[lang] else {})) for name in names])
                    for lang, names in CASES.items()}
        subjects['go']['hpke_build'] = {'status': 'PASS'}
        self.assertTrue(successful(subjects))
        self.assertFalse(successful({}))
        for mode in ('build', 'missing', 'failed', 'duplicate', 'identity', 'schedule_failed'):
            value = copy.deepcopy(subjects)
            if mode == 'build': value['go']['build']['status'] = 'FAIL'
            if mode == 'missing': value['go']['cases'].pop()
            if mode == 'failed': value['rust']['cases'][0]['status'] = 'FAIL'
            if mode == 'duplicate': value['go']['cases'].append(value['go']['cases'][0])
            if mode == 'schedule_failed': value['rust']['cases'][-1]['status'] = 'FAIL'
            if mode == 'identity': value['go']['cases'][0]['test'] = 'other'
            self.assertFalse(successful(value), mode)
        value = copy.deepcopy(subjects)
        owner = next(row for row in value['go']['cases'] if 'owner_admission_boundaries' in row)
        owner['owner_admission_boundaries'] = ['owner-isolation']
        self.assertFalse(successful(value))
        value = copy.deepcopy(subjects)
        signature = next(row for row in value['rust']['cases']
                         if row.get('signature_boundary') == 'result-algorithm')
        signature['signature_boundary'] = 'intent-algorithm'
        self.assertFalse(successful(value))

    def test_cli_preserves_existing_output_and_failed_snapshot(self):
        script = ROOT / 'scripts/run_mcp_core_runtime.py'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'missing-core'
            repo.mkdir()
            output = root / 'evidence'
            command = [sys.executable, '-B', str(script), '--go', str(repo),
                       '--rust', str(repo), '--output', str(output)]
            failed = subprocess.run(command, capture_output=True, timeout=5)
            self.assertNotEqual(failed.returncode, 0)
            original = (output / 'report.json').read_bytes()
            report = json.loads(original)
            self.assertEqual(report['status'], 'FAIL')
            self.assertEqual(report['subjects'], {})
            self.assertEqual(report['interoperability'], 'NOT_RUN')
            self.assertEqual(report['catalog'], {'NOT_RUN': 71})
            again = subprocess.run(command, capture_output=True, timeout=5)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual((output / 'report.json').read_bytes(), original)
            nested = subprocess.run(command[:-1] + [str(repo / 'output')],
                                    capture_output=True, timeout=5)
            self.assertNotEqual(nested.returncode, 0)
            self.assertFalse((repo / 'output').exists())

    def test_bounded_process_and_failure_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [('ok', 'print("local fixture")', 2, 'PASS'),
                     ('fail', 'raise SystemExit(7)', 2, 'FAIL'),
                     ('timeout', 'import time; time.sleep(5)', .05, 'TIMEOUT')]
            for label, code, timeout, expected in cases:
                row = run([sys.executable, '-c', code], root, root / (label + '.log'), timeout)
                self.assertEqual(row['status'], expected)
                self.assertEqual(len(row['log_sha256']), 64)
                self.assertTrue((root / row['log']).exists())
            with self.assertRaises(FileExistsError):
                run([sys.executable, '-c', 'pass'], root, root / 'ok.log', 2)


if __name__ == '__main__':
    unittest.main()
