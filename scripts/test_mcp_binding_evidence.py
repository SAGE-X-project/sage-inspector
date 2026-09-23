"""Fail-closed controls for the combined MCP binding evidence verdict."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_mcp_binding_evidence as checker


class BindingEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.runtime, self.parents, self.interop = [self.base / name
                                                     for name in ('runtime', 'parents', 'interop')]
        for path in (self.runtime, self.parents, self.interop):
            path.mkdir()
        subjects = {}
        for language in checker.LANGUAGES:
            rows = []
            for index, (test, children) in enumerate(checker.NORMATIVE_CONTRACT_CASES[language].items()):
                raw = b'exact selected test log\n'
                log = f'{language}-{index}.log'
                (self.runtime / log).write_bytes(raw)
                rows.append({'test': test, 'status': 'PASS', 'execution_status': 'PASS',
                             'exit_code': 0, 'log': log, 'log_sha256': checker.sha(raw),
                             'mandatory_children': children})
            subjects[language] = {'revision': checker.PINS[language], 'cases': rows}
            contract = checker.NORMATIVE_CONTRACTS[language]
            (self.runtime / (language + '-normative-review-contract.json')).write_bytes(contract.read_bytes())
        self.runtime_report = {
            'kind': 'mcp-core-runtime-tests', 'status': 'PASS',
            'conformance': 'NOT_ESTABLISHED', 'catalog': {'NOT_RUN': 71},
            'mandatory_children': 'PINNED_CORE_ASSERTIONS', 'subjects': subjects,
            'normative_contract_sha256': {language: checker.sha(path.read_bytes())
                                          for language, path in checker.NORMATIVE_CONTRACTS.items()},
        }
        self.save_runtime()
        runtime_raw = (self.runtime / 'report.json').read_bytes()
        self.parent_report = {
            'kind': 'mcp-proposal-case-runtime-evidence', 'status': 'EVIDENCE_CHECKED',
            'historical_catalog': {'NOT_RUN': 71},
            'runtime_case_counts': {'PASS': 71, 'PARTIAL': 0, 'NOT_RUN': 0},
            'conformance': 'NOT_ESTABLISHED', 'runtime_report_sha256': checker.sha(runtime_raw),
            'cases': [{'id': row['id'], 'status': 'PASS'} for row in checker.catalog_rows()],
        }
        (self.parents / 'report.json').write_text(json.dumps(self.parent_report) + '\n')
        pairs, restarts = [], []
        for pair in sorted(checker.PAIRS):
            directory = self.interop / pair
            directory.mkdir()
            files = self.frames(directory, 5)
            files.update(self.journals(directory))
            pairs.append({'pair': pair, 'status': 'PASS', 'effects': 1,
                          'execution_transitions': ['RESERVED', 'EXECUTING', 'COMPLETED'],
                          'protected_exchanges': 1, 'terminal_records': 1,
                          'setup_signature_checks': 9, 'protected_signature_checks': 4,
                          'independent_signatures': 13, 'frames': 10,
                          'files': files})
            for mode in ('server', 'client'):
                reopened = self.interop / ('reopen-' + mode) / pair
                reopened.mkdir(parents=True)
                files = self.frames(reopened, 5 if mode == 'server' else 4)
                files.update(self.journals(reopened, before=True))
                row = {'pair': pair, 'status': 'PASS', 'effects': 0,
                       'restart_mode': mode, 'recovery': mode,
                       'server_journal_unchanged': True,
                       'protected_exchanges': 1 if mode == 'server' else 0,
                       'frames': 10 if mode == 'server' else 8, 'files': files}
                if mode == 'client':
                    row['client_journal_unchanged'] = True
                restarts.append(row)
        self.interop_report = {
            'kind': 'mcp-native-protected-interop', 'status': 'PASS',
            'protected_dispatch': 'PASS', 'completed_recovery': 'SELECTED_ASSERTIONS_PASS',
            'conformance': 'NOT_ESTABLISHED', 'pairs': pairs, 'restart': restarts,
            'subjects': {language: {'revision': checker.PINS[language],
                                    'build': {'status': 'PASS'}}
                         for language in checker.LANGUAGES},
        }
        self.save_interop()

    def tearDown(self):
        self.temp.cleanup()

    def frames(self, directory, count):
        raw = json.dumps({'requests': ['00'] * count, 'responses': ['01'] * count}).encode()
        (directory / 'frames.json').write_bytes(raw)
        return {'frames.json': checker.sha(raw)}

    def journals(self, directory, before=False):
        result = {}
        for name in ('server.journal', 'client.journal'):
            raw = (name + ' local fixture').encode()
            (directory / name).write_bytes(raw)
            result[name] = checker.sha(raw)
            if before:
                (directory / (name + '.before')).write_bytes(raw)
                result[name + '.before'] = checker.sha(raw)
        return result

    def save_runtime(self):
        (self.runtime / 'report.json').write_text(json.dumps(self.runtime_report) + '\n')

    def save_interop(self):
        (self.interop / 'report.json').write_text(json.dumps(self.interop_report) + '\n')

    @patch.object(checker, 'successful', return_value=True)
    @patch.object(checker, 'observed', return_value=True)
    def test_combined_evidence_remains_conservative(self, _observed, _successful):
        report = checker.inspect(self.runtime, self.parents, self.interop)
        self.assertEqual(report['current_parent_cases']['PASS'], 71)
        self.assertEqual(report['historical_catalog'], {'NOT_RUN': 71})
        self.assertEqual(report['mandatory_children']['go']['mandatory_children'], 26)
        self.assertEqual(report['mandatory_children']['rust']['mandatory_children'], 26)
        self.assertEqual(report['protected_pairs'], {'PASS': 4})
        self.assertEqual(report['restart_observations'], {'PASS': 8})
        self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')

    @patch.object(checker, 'successful', return_value=True)
    @patch.object(checker, 'observed', return_value=True)
    def test_missing_child_or_changed_restart_fails(self, _observed, _successful):
        original = copy.deepcopy(self.runtime_report)
        self.runtime_report['subjects']['go']['cases'].pop()
        self.save_runtime()
        with self.assertRaisesRegex(ValueError, 'mandatory child count'):
            checker.runtime_evidence(self.runtime)
        self.runtime_report = original
        self.save_runtime()
        self.interop_report['restart'][0]['server_journal_unchanged'] = False
        self.save_interop()
        with self.assertRaisesRegex(ValueError, 'server journal mutation'):
            checker.interop_evidence(self.interop)

    @patch.object(checker, 'successful', return_value=True)
    @patch.object(checker, 'observed', return_value=True)
    def test_parent_history_and_frame_hash_are_fail_closed(self, _observed, _successful):
        changed = copy.deepcopy(self.parent_report)
        changed['historical_catalog'] = {'PASS': 71}
        (self.parents / 'report.json').write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'parent case claim promotion'):
            checker.parent_evidence(self.parents, (self.runtime / 'report.json').read_bytes())
        (self.parents / 'report.json').write_text(json.dumps(self.parent_report) + '\n')
        pair = self.interop_report['pairs'][0]
        (self.interop / pair['pair'] / 'frames.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'interop evidence hash'):
            checker.interop_evidence(self.interop)


if __name__ == '__main__':
    unittest.main()
