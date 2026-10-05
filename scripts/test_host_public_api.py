"""Reject incomplete or promoted public API evidence and source drift."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import inspect_host_public_api as api


class HostPublicAPITest(unittest.TestCase):
    def setUp(self):
        self.suite = api.catalog()
        self.report = api.expected_report(self.suite)

    def test_saved_evidence_covers_all_ports_with_limits(self):
        saved = json.loads(api.REPORT.read_text())
        self.assertEqual(api.check_report(saved), 9)
        self.assertEqual(saved['deployed_host'], 'NOT_RUN')
        self.assertEqual(saved['protected_intent_issuance'], 'NOT_RUN')
        self.assertEqual(saved['full_conformance'], 'NOT_ESTABLISHED')

    def test_compilation_cannot_be_promoted(self):
        for field in ('status', 'deployed_host', 'full_conformance', 'protected_intent_issuance'):
            report = copy.deepcopy(self.report)
            report[field] = 'PASS'
            with self.subTest(field=field), self.assertRaises(ValueError):
                api.check_report(report)

    def test_port_omission_duplication_and_changed_gap_are_rejected(self):
        candidates = []
        missing = copy.deepcopy(self.report)
        missing['ports'].pop()
        candidates.append(missing)
        duplicate = copy.deepcopy(self.report)
        duplicate['ports'][-1] = duplicate['ports'][0]
        candidates.append(duplicate)
        gap = copy.deepcopy(self.report)
        gap['ports'][4]['gap'] = None
        candidates.append(gap)
        for report in candidates:
            with self.subTest(report=report['ports'][-1]['port']), self.assertRaises(ValueError):
                api.check_report(report)

    def test_revision_hash_and_private_access_forgery_are_rejected(self):
        for field, value in (('schema_version', True), ('go_revision', '0' * 40), ('catalog_sha256', '0' * 64),
                             ('host_contract_sha256', '0' * 64),
                             ('private_assembly', {'go': 'IMPORTABLE', 'rust': 'IMPORTABLE'})):
            report = copy.deepcopy(self.report)
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                api.check_report(report)

    def test_catalog_cannot_hide_missing_signer_or_inject_probe_code(self):
        for mode in ('missing', 'gap', 'coverage', 'injection'):
            suite = copy.deepcopy(self.suite)
            if mode == 'missing':
                suite['ports'].pop()
            elif mode == 'gap':
                suite['ports'][4]['gap'] = ''
            elif mode == 'coverage':
                suite['ports'][4]['coverage'] = 'PUBLIC_PRIMITIVE'
            else:
                suite['ports'][0]['go']['references'] = ['NewRootCapture;panic("oops")']
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'catalog.json'
                path.write_text(json.dumps(suite))
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    api.catalog(path)

    def test_changed_source_fails_before_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / next(iter(self.suite['ports'][0]['go']['sources']))
            path.parent.mkdir(parents=True)
            path.write_text('changed source')
            with patch.object(api, 'check_source', return_value=root), \
                    patch.object(api.subprocess, 'check_output', return_value=''), \
                    patch.object(api, 'compile_probes') as compiler:
                with self.assertRaisesRegex(ValueError, 'source drift'):
                    api.inspect(root, root)
                compiler.assert_not_called()

    def test_untracked_core_source_fails_before_compilation(self):
        with patch.object(api, 'check_source', return_value=Path('/unused')), \
                patch.object(api.subprocess, 'check_output', return_value='?? injected.go\n'), \
                patch.object(api, 'compile_probes') as compiler:
            with self.assertRaisesRegex(ValueError, 'untracked'):
                api.inspect(Path('/unused'), Path('/unused'))
            compiler.assert_not_called()

    def test_unrelated_compile_failure_is_not_private_access_evidence(self):
        for language in ('go', 'rust'):
            result = subprocess.CompletedProcess([], 1, '', 'dependency missing')
            with self.subTest(language=language), self.assertRaises(ValueError):
                api.check_private_rejection(language, result)
            result = subprocess.CompletedProcess([], 0, '', 'guard010.newMCPHost undefined:')
            with self.subTest(language=language), self.assertRaises(ValueError):
                api.check_private_rejection(language, result)


if __name__ == '__main__':
    unittest.main()
