"""Exercise the local review CLI; no agent, registry or protected tool is run."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from inspect_guard_integration import ROOT, CONTRACT, sha


class ReviewCLI(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/inspect_guard_integration.py'),
                               *map(str, args)], cwd=ROOT, capture_output=True, text=True, timeout=20)

    def test_report_preservation_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / 'report'
            result = self.run_cli('--output', output)
            self.assertEqual(result.returncode, 3, result.stderr)
            raw = (output / 'report.json').read_bytes()
            report = json.loads(raw)
            self.assertEqual(report['contract_sha256'], sha((ROOT / CONTRACT).read_bytes()))
            self.assertEqual((output / 'contract.json').read_bytes(), (ROOT / CONTRACT).read_bytes())
            self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
            self.assertFalse(report['actual_core_execution'])
            self.assertTrue(all(x['status'] == 'NOT_CHECKED' for x in report['source_identity'].values()))
            self.assertEqual(self.run_cli('--output', output).returncode, 2)
            self.assertEqual((output / 'report.json').read_bytes(), raw)
            failed = base / 'missing-core'
            self.assertEqual(self.run_cli('--output', failed, '--go-root', base / 'absent').returncode, 2)
            self.assertFalse(failed.exists())
            self.assertEqual(self.run_cli('--output', ROOT / 'docs/evidence/forbidden-review').returncode, 2)
            self.assertEqual(self.run_cli('--output', ROOT).returncode, 2)


if __name__ == '__main__':
    unittest.main()
