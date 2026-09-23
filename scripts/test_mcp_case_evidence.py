"""Controls for conservative MCP proposal-case evidence promotion."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import check_mcp_case_evidence as checker
from run_mcp_core_runtime import (CASES, OWNER_CONTRACT, OWNER_CONTRACT_CASES, PINS,
                                  SIGNATURE_CONTRACT, SIGNATURE_CONTRACT_CASES)


def go_log(name):
    return f'=== RUN   {name}\n--- PASS: {name} (0.01s)\nPASS\n'.encode()


def rust_log(name):
    return (f'test {name} ... ok\n\n'
            'test result: ok. 1 passed; 0 failed; 0 ignored; 99 filtered out;\n').encode()


class CaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.runtime = self.base / 'runtime'
        self.runtime.mkdir()
        (self.runtime / 'owner-admission-contract.json').write_bytes(OWNER_CONTRACT.read_bytes())
        (self.runtime / 'signature-boundary-contract.json').write_bytes(SIGNATURE_CONTRACT.read_bytes())
        runner = b'pinned synthetic runtime runner\n'
        (self.runtime / 'runner.py').write_bytes(runner)
        subjects = {}
        for language, names in CASES.items():
            rows = []
            for index, name in enumerate(names):
                row = {'test': name, 'status': 'PASS'}
                if name in OWNER_CONTRACT_CASES[language]:
                    row['owner_admission_boundaries'] = OWNER_CONTRACT_CASES[language][name]
                if name in SIGNATURE_CONTRACT_CASES[language]:
                    row['signature_boundary'] = SIGNATURE_CONTRACT_CASES[language][name]
                required = {test for assessment in checker.ASSESSMENTS.values()
                            for _, test in assessment['requirements']}
                if name in required:
                    raw = go_log(name) if language == 'go' else rust_log(name)
                    log = f'{language}-{index}.log'
                    (self.runtime / log).write_bytes(raw)
                    row.update(execution_status='PASS', exit_code=0,
                               evidence_kind='pinned-core-assertions', log=log,
                               log_sha256=checker.sha(raw))
                rows.append(row)
            subjects[language] = {'revision': PINS[language], 'build': {'status': 'PASS'},
                                  'cases': rows}
        self.report = {
            'kind': 'mcp-core-runtime-tests', 'status': 'PASS',
            'conformance': 'NOT_ESTABLISHED', 'interoperability': 'NOT_RUN',
            'catalog': {'NOT_RUN': 71}, 'mandatory_children': 'NOT_PROMOTED',
            'owner_admission_contract_sha256': checker.sha(OWNER_CONTRACT.read_bytes()),
            'signature_boundary_contract_sha256': checker.sha(SIGNATURE_CONTRACT.read_bytes()),
            'runner_sha256': checker.sha(runner), 'inspector_revision': '1' * 40,
            'subjects': subjects,
        }
        self.save()

    def tearDown(self):
        self.temporary.cleanup()

    def save(self):
        (self.runtime / 'report.json').write_text(json.dumps(self.report, indent=2) + '\n')

    def test_complete_and_not_run_results_are_distinct(self):
        result = checker.inspect(self.runtime)
        self.assertEqual(result['status'], 'EVIDENCE_CHECKED')
        self.assertEqual(result['runtime_case_counts'], {'PASS': 8, 'PARTIAL': 0, 'NOT_RUN': 63})
        self.assertEqual(result['historical_catalog'], {'NOT_RUN': 71})
        self.assertEqual(result['conformance'], 'NOT_ESTABLISHED')
        statuses = {row['id']: row['status'] for row in result['cases']}
        self.assertEqual(statuses['mres-close-after-admission'], 'PASS')
        self.assertEqual(statuses['mres-close-after-reservation'], 'PASS')
        self.assertEqual(statuses['mres-crash-after-admission'], 'PASS')
        self.assertEqual(statuses['mres-protected-timeout-before-admission'], 'PASS')
        self.assertEqual(statuses['mres-protected-timeout-after-admission'], 'PASS')
        self.assertEqual(statuses['mres-ready-session-expiry'], 'PASS')
        self.assertEqual(statuses['mres-signature-intent'], 'PASS')
        self.assertEqual(statuses['mres-signature-result'], 'PASS')
        self.assertEqual(len(result['cases']), 71)
        for case in result['cases']:
            for row in case.get('evidence', []):
                self.assertEqual(row['revision'], PINS[row['language']])

    def test_changed_or_rehashed_log_fails(self):
        row = next(row for row in self.report['subjects']['go']['cases']
                   if row['test'] == 'TestMCPAdmissionCloseDuringFence')
        path = self.runtime / row['log']
        path.write_bytes(b'PASS\n')
        with self.assertRaisesRegex(ValueError, 'required log hash'):
            checker.inspect(self.runtime)
        row['log_sha256'] = checker.sha(path.read_bytes())
        self.save()
        with self.assertRaisesRegex(ValueError, 'required test not observed'):
            checker.inspect(self.runtime)

    def test_runtime_failure_or_claim_promotion_fails(self):
        for change in (
                lambda value: value.update(status='FAIL'),
                lambda value: value.update(conformance='PASS'),
                lambda value: value.update(catalog={'PASS': 71}),
                lambda value: value['subjects']['rust']['cases'].pop()):
            original = copy.deepcopy(self.report)
            change(self.report)
            self.save()
            with self.subTest(change=change), self.assertRaises(ValueError):
                checker.inspect(self.runtime)
            self.report = original

    def test_contract_rejects_new_or_changed_promotions(self):
        value = checker.load(checker.CONTRACT.read_bytes())
        for change in (
                lambda item: item.update(conformance='PASS'),
                lambda item: item['assessments'].pop(),
                lambda item: item['assessments'][0].update(status='PARTIAL'),
                lambda item: item['assessments'][0]['requirements'][0].update(test='other'),
                lambda item: item.update(runtime_case_counts={'PASS': 71})):
            candidate = copy.deepcopy(value)
            change(candidate)
            with self.subTest(change=change), self.assertRaises(ValueError):
                checker.validate_contract(candidate)

    def test_cli_preserves_report_and_refuses_overwrite(self):
        output = self.base / 'output'
        command = [sys.executable, '-B', str(checker.ROOT / 'scripts/check_mcp_case_evidence.py'),
                   '--runtime', str(self.runtime), '--output', str(output)]
        result = subprocess.run(command, cwd=checker.ROOT, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = (output / 'report.json').read_bytes()
        self.assertEqual(json.loads(raw)['runtime_case_counts'],
                         {'PASS': 8, 'PARTIAL': 0, 'NOT_RUN': 63})
        self.assertEqual((output / 'contract.json').read_bytes(), checker.CONTRACT.read_bytes())
        result = subprocess.run(command, cwd=checker.ROOT, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((output / 'report.json').read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
