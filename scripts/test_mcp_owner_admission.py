"""Negative controls for the MCP owner/admission source contract."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import check_mcp_owner_admission as checker


class OwnerAdmissionContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = checker.load(checker.CONTRACT.read_bytes())

    def reject(self, change):
        candidate = copy.deepcopy(self.contract)
        change(candidate)
        with self.assertRaises((ValueError, TypeError)):
            checker.validate(candidate)

    def test_contract_covers_every_boundary_in_each_core(self):
        report = checker.audit()
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['runtime'], 'NOT_RUN')
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
        self.assertEqual(report['selected_tests'], {'go': 6, 'rust': 6})
        self.assertTrue(all(row['status'] == 'NOT_CHECKED' for row in report['source_identity'].values()))

    def test_rejects_claim_promotion_and_incomplete_coverage(self):
        self.reject(lambda value: value.update(conformance='PASS'))
        self.reject(lambda value: value['boundaries'].pop())
        self.reject(lambda value: value['cores']['go']['tests'].clear())
        self.reject(lambda value: value['cores']['rust']['tests'].__setitem__('extra test', ['unknown']))
        self.reject(lambda value: value['cores']['go']['files'].pop('pkg/agent/guard010/mcp_owner.go'))
        self.reject(lambda value: value['cores']['rust']['tests'].__setitem__(
            next(iter(value['cores']['rust']['tests'])), ['owner-isolation']))

    def test_rejects_ambiguous_or_changed_sources(self):
        with self.assertRaises(ValueError):
            checker.load(b'{"kind":"one","kind":"two"}')
        self.reject(lambda value: value['cores']['go'].update(revision='main'))
        self.reject(lambda value: value['cores']['rust']['files'].update({'../escape': '0' * 64}))
        with mock.patch.object(checker.subprocess, 'check_output', return_value=self.contract['cores']['go']['revision']), \
                mock.patch.object(checker, 'read', return_value=b'changed'):
            with self.assertRaisesRegex(ValueError, 'core source mismatch'):
                checker.audit({'go': checker.ROOT})

    def test_cli_preserves_contract_and_rejects_overwrite(self):
        script = checker.ROOT / 'scripts/check_mcp_owner_admission.py'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'audit'
            result = subprocess.run([sys.executable, '-B', str(script), '--output', str(output)],
                                    cwd=checker.ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((output / 'report.json').read_bytes())
            self.assertEqual(report['contract_sha256'], checker.sha(checker.CONTRACT.read_bytes()))
            self.assertEqual((output / 'contract.json').read_bytes(), checker.CONTRACT.read_bytes())
            again = subprocess.run([sys.executable, '-B', str(script), '--output', str(output)],
                                   cwd=checker.ROOT, capture_output=True, timeout=10)
            self.assertEqual(again.returncode, 2)

    def test_cli_does_not_create_output_for_bad_core(self):
        script = checker.ROOT / 'scripts/check_mcp_owner_admission.py'
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / 'audit'
            result = subprocess.run([sys.executable, '-B', str(script), '--go-root', str(base),
                                     '--output', str(output)], cwd=checker.ROOT,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
