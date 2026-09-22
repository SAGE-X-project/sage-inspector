"""Evidence classifier controls and harmless bounded process runtime tests."""
import copy
from pathlib import Path
import sys
import json
import subprocess
import tempfile
import unittest
from run_mcp_core_runtime import CASES, ROOT, observed, run, successful


class EvidenceTests(unittest.TestCase):
    def test_go_requires_exact_execution(self):
        text = '=== RUN   Sample\n--- PASS: Sample (0.01s)\nPASS\n'
        self.assertTrue(observed('go', 'Sample', text, 0))
        for bad in ('PASS\n', text.replace('Sample', 'Other'),
                    text.replace('PASS:', 'SKIP:'), text + text):
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
        subjects = {lang: dict(build=dict(status='PASS'), cases=[dict(test=name, status='PASS')
                    for name in names]) for lang, names in CASES.items()}
        self.assertTrue(successful(subjects))
        self.assertFalse(successful({}))
        for mode in ('build', 'missing', 'failed', 'duplicate', 'identity'):
            value = copy.deepcopy(subjects)
            if mode == 'build': value['go']['build']['status'] = 'FAIL'
            if mode == 'missing': value['go']['cases'].pop()
            if mode == 'failed': value['rust']['cases'][0]['status'] = 'FAIL'
            if mode == 'duplicate': value['go']['cases'].append(value['go']['cases'][0])
            if mode == 'identity': value['go']['cases'][0]['test'] = 'other'
            self.assertFalse(successful(value), mode)

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
