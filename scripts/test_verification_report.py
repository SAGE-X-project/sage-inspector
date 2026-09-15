"""Test report failure semantics with inert local Python processes."""
from pathlib import Path
import sys
import tempfile
import unittest
from run_verification_tests import run_command, sha256, summarize


class VerificationReportTests(unittest.TestCase):
    def test_process_results_and_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for code in (0, 7):
                result = run_command([sys.executable, '-c', f'print("recorded");raise SystemExit({code})'], root, str(code))
                self.assertEqual(result['exit_code'], code)
                self.assertEqual(result['status'], 'PASS' if code == 0 else 'FAIL')
                self.assertIn('recorded', (root/result['log']).read_text())
                self.assertEqual(result['log_sha256'], sha256(root/result['log']))

    def test_timeout_and_missing_process_are_not_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_command([sys.executable, '-c', 'import time;time.sleep(10)'], root, 'timeout', timeout=0.2)
            self.assertEqual(result['status'], 'TIMEOUT')
            self.assertIsNone(result['exit_code'])
            result = run_command([str(root/'absent')], root, 'missing')
            self.assertEqual(result['status'], 'ERROR')
            self.assertTrue(result['reason'])

    def test_only_complete_success_can_pass(self):
        good = dict(status='PASS', exit_code=0)
        self.assertEqual(summarize([good], 1), 'PASS')
        self.assertEqual(summarize([], 1), 'FAIL')
        for status, code in [('FAIL',1), ('TIMEOUT',None), ('ERROR',None), ('NOT_RUN',None), ('PASS',7)]:
            self.assertEqual(summarize([dict(status=status,exit_code=code)], 1), 'FAIL')


if __name__ == '__main__':
    unittest.main()
