"""Corrupted-record and scope tests; no network or attack reproduction."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
import inspect_public_mcp_host as audit


class PublicMCPHostTests(unittest.TestCase):
    def setUp(self):
        self.report = audit.strict_json(audit.REPORT.read_bytes())

    def rewrite(self, case, mode, field, change):
        header = audit.HEADER if field == 'journal_hex' else audit.LEDGER
        raw = bytes.fromhex(case[mode][field])
        rows = [json.loads(line) for line in raw[len(header):].splitlines()]
        change(rows)
        case[mode][field] = (header + b''.join(json.dumps(row, separators=(',', ':')).encode() + b'\n' for row in rows)).hex()

    def test_saved_native_observations(self):
        self.assertEqual(audit.check_report(self.report), 4)

    def test_scope_promotions_and_provenance_drift_reject(self):
        for field in audit.SCOPE:
            report = copy.deepcopy(self.report); report['scope'][field] = 'PASS'
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit.check_report(report)
        for field in ('go_revision', 'rust_revision', 'fixture_sha256', 'compiler_status'):
            report = copy.deepcopy(self.report); report[field] = 'changed'
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit.check_report(report)

    def test_all_four_directions_required_once(self):
        report = copy.deepcopy(self.report); report['cases'].pop()
        with self.assertRaises(ValueError): audit.check_report(report)
        report = copy.deepcopy(self.report); report['cases'][1] = report['cases'][0]
        with self.assertRaises(ValueError): audit.check_report(report)

    def test_effect_count_must_be_exactly_one(self):
        for count in (0, 2, True):
            case = copy.deepcopy(self.report['cases'][0]); case['server']['effects'] = count
            with self.subTest(count=count), self.assertRaises(ValueError): audit.check_case(case)

    def test_original_and_result_binding_reject(self):
        for field, index, signed_field in [('journal_hex', 0, 'intent'), ('journal_hex', -1, 'result')]:
            case = copy.deepcopy(self.report['cases'][0])
            def change(rows):
                key = 'intent_hex' if signed_field == 'intent' else 'result_hex'
                env = json.loads(bytes.fromhex(rows[index][key]))
                env[signed_field]['original_digest' if signed_field == 'intent' else 'intent_digest'] = '0' * 64
                rows[index][key] = audit.canonical(env).hex()
            self.rewrite(case, 'client', field, change)
            with self.subTest(field=signed_field), self.assertRaises(InvalidSignature): audit.check_case(case)

    def test_terminal_and_ledger_agree(self):
        case = copy.deepcopy(self.report['cases'][0])
        self.rewrite(case, 'server', 'ledger_hex', lambda rows: rows[-1].update(result_hex=''))
        with self.assertRaisesRegex(ValueError, 'one durable execution'): audit.check_case(case)
        case = copy.deepcopy(self.report['cases'][0])
        self.rewrite(case, 'server', 'ledger_hex', lambda rows: rows.append(rows[-1]))
        with self.assertRaises(ValueError): audit.check_case(case)

    def test_retry_identity_and_cadence_reject(self):
        case = copy.deepcopy(self.report['cases'][0])
        self.rewrite(case, 'client', 'journal_hex', lambda rows: rows[2].update(id='00000000-0000-4000-8000-000000000099'))
        with self.assertRaisesRegex(ValueError, 'retry cadence'): audit.check_case(case)
        case = copy.deepcopy(self.report['cases'][0])
        self.rewrite(case, 'client', 'journal_hex', lambda rows: rows[1].update(at=459999))
        with self.assertRaisesRegex(ValueError, 'retry cadence'): audit.check_case(case)

    def test_duplicate_or_nonfinite_json_reject(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): audit.strict_json(raw)

    def test_valid_fixture_signature_still_requires_captured_original(self):
        case = copy.deepcopy(self.report['cases'][0])
        def change(rows):
            env = json.loads(bytes.fromhex(rows[0]['intent_hex']))
            env['intent']['original_digest'] = '0' * 64
            signer = audit.Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
            proof = signer.sign(b'sage-execution-intent|0.10.0\0' + audit.canonical(env['intent']))
            env['proof'] = audit.base64.urlsafe_b64encode(proof).rstrip(b'=').decode()
            rows[0]['intent_hex'] = audit.canonical(env).hex()
        self.rewrite(case, 'client', 'journal_hex', change)
        with self.assertRaisesRegex(ValueError, 'captured root binding'): audit.check_case(case)

    def test_boolean_is_not_an_integer_journal_timestamp(self):
        case = copy.deepcopy(self.report['cases'][0])
        self.rewrite(case, 'client', 'journal_hex', lambda rows: rows[0].update(at=False))
        with self.assertRaises(ValueError): audit.check_case(case)

    def test_zero_tests_is_not_native_evidence(self):
        for lang in ('go', 'rust'):
            done = subprocess.CompletedProcess([], 0, b'no tests executed')
            with self.subTest(lang=lang), self.assertRaises(ValueError): audit.executed(lang, done)

    def test_lock_and_source_drift_reject_before_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / 'Cargo.lock'; lock.write_text('unreviewed')
            with patch.object(audit, 'RUST_LOCK', lock), patch.object(audit, 'build') as compiler:
                with self.assertRaises(ValueError): audit.inspect(Path('/go'), Path('/rust'))
                compiler.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / 'Cargo.lock'; lock.write_text('unreviewed external consumer')
            with patch.object(audit, 'PROBE_LOCK', lock), patch.object(audit, 'build') as compiler:
                with self.assertRaises(ValueError): audit.inspect(Path('/go'), Path('/rust'))
                compiler.assert_not_called()
        with patch.object(audit, 'check_source', side_effect=ValueError('unreviewed source')), patch.object(audit, 'build') as compiler:
            with self.assertRaises(ValueError): audit.inspect(Path('/go'), Path('/rust'))
            compiler.assert_not_called()


if __name__ == '__main__':
    unittest.main()
