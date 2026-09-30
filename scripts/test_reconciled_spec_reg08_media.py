"""Exercise the new bounded media oracle in-process and as a local CLI."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import reconciled_spec_reg08_media as checker


class ReconciledReg08MediaTests(unittest.TestCase):
    def test_every_case_and_provenance(self):
        result = checker.check()
        self.assertEqual(result['checked_subconditions'], 13)
        self.assertEqual(result['parent_cases']['REG-08-N04'], 'NOT_RUN')
        self.assertEqual(result['core_implementation'], 'NOT_RUN')

    def test_negative_media_controls(self):
        valid = {'header_lines': [['Content-Type', 'Application/JSON']]}
        self.assertEqual(checker.decision(valid), 'MEDIA_ACCEPT')
        for row in (
            {'header_lines': []},
            {'header_lines': [['Content-Type', 'application/json; charset=utf-8']]},
            {'header_lines': [['Content-Type', 'application/json'],
                              ['content-type', 'application/json']]},
            {'header_lines': [['Content-Type', 'application/json'],
                              ['Content-Encoding', 'identity']]},
            {'header_lines': [['Content-Type', 'application/json']],
             'trailer_lines': [['Content-Type', 'application/json']]},
        ):
            self.assertEqual(checker.decision(row), 'RECORD_INVALID')

    def test_runtime_cli_keeps_parent_unexecuted(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'report.json'
            result = subprocess.run([
                sys.executable, '-B', str(checker.ROOT / 'scripts/reconciled_spec_reg08_media.py'),
                '--report', str(report)], capture_output=True, text=True,
                timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads(report.read_bytes())
            self.assertEqual(record['web_origin'], 'NOT_RUN')
            self.assertEqual(record['conformance'], 'NOT_ESTABLISHED')


if __name__ == '__main__':
    unittest.main()
