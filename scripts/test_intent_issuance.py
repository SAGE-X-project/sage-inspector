"""Reject promoted or corrupted native issuance evidence."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import inspect_intent_issuance as audit


class IssuanceEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(audit.EVIDENCE.read_text())

    def test_saved_report_is_independently_verified(self):
        self.assertEqual(audit.check_report(self.report), 4)

    def test_compiled_native_observations_cannot_promote_host_or_hop(self):
        for field in ('status', 'deployed_host', 'independent_hop_execution', 'full_conformance'):
            report = copy.deepcopy(self.report)
            report[field] = 'PASS'
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit.check_report(report)

    def test_provenance_type_revision_and_source_drift_are_rejected(self):
        for field, value in (('schema_version', True), ('go_revision', '0' * 40),
                             ('fixture_sha256', '0' * 64), ('source_sha256', {})):
            report = copy.deepcopy(self.report)
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit.check_report(report)

    def test_valid_signature_cannot_replace_the_original_capture(self):
        row = self.report['cases'][0]
        before = bytes.fromhex(row['before_hex'])
        after = bytes.fromhex(row['after_hex'])
        rows = [json.loads(line) for line in after[len(audit.HEADER):].splitlines()]
        envelope = json.loads(bytes.fromhex(rows[0]['intent_hex']))
        envelope['intent']['original_digest'] = '0' * 64
        key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'public Guard fixture issuer').digest())
        proof = key.sign(b'sage-execution-intent|0.10.0\0' + audit.canonical(envelope['intent']))
        envelope['proof'] = base64.urlsafe_b64encode(proof).rstrip(b'=').decode()
        rows[0]['intent_hex'] = audit.canonical(envelope).hex()
        wire = lambda records: audit.HEADER + b''.join(json.dumps(item, separators=(',', ':')).encode() + b'\n' for item in records)
        self.assertNotEqual(before, wire(rows[:2]))
        with self.assertRaisesRegex(ValueError, 'protected issuance binding'):
            audit.check_journals(wire(rows[:2]), wire(rows), audit.FENCE +
                                 audit.sha(audit.canonical(envelope['intent'])).encode() + b'\n')

    def test_invalid_proof_and_journal_replacement_are_rejected(self):
        row = self.report['cases'][0]
        before = bytes.fromhex(row['before_hex'])
        after = bytes.fromhex(row['after_hex'])
        with self.assertRaises(ValueError):
            audit.check_journals(before, after[1:], bytes.fromhex(row['fence_hex']))
        rows = [json.loads(line) for line in after[len(audit.HEADER):].splitlines()]
        envelope = json.loads(bytes.fromhex(rows[0]['intent_hex']))
        proof = bytearray(base64.urlsafe_b64decode(envelope['proof'] + '=='))
        proof[0] ^= 1
        envelope['proof'] = base64.urlsafe_b64encode(proof).rstrip(b'=').decode()
        rows[0]['intent_hex'] = audit.canonical(envelope).hex()
        wire = lambda records: audit.HEADER + b''.join(json.dumps(item, separators=(',', ':')).encode() + b'\n' for item in records)
        with self.assertRaises(InvalidSignature):
            audit.check_journals(wire(rows[:2]), wire(rows), bytes.fromhex(row['fence_hex']))

    def test_fence_replacement_and_missing_case_are_rejected(self):
        report = copy.deepcopy(self.report)
        report['cases'][1]['after_fence_hex'] = (audit.FENCE + b'0' * 64 + b'\n').hex()
        with self.assertRaises(ValueError):
            audit.check_report(report)
        report = copy.deepcopy(self.report)
        report['cases'].pop()
        with self.assertRaises(ValueError):
            audit.check_report(report)

    def test_helper_success_without_executed_test_is_not_evidence(self):
        result = subprocess.CompletedProcess([], 0, b'no tests executed', b'')
        for language in ('go', 'rust'):
            with patch.object(audit.subprocess, 'run', return_value=result), \
                    self.subTest(language=language), self.assertRaises(ValueError):
                audit.run(language, {'go': Path('/go'), 'rust': Path('/rust')},
                          {'go': Path('/source'), 'rust': Path('/source')}, Path('/journal'), 'issue')

    def test_wrong_source_revision_fails_before_compilation(self):
        with patch.object(audit, 'check_source', side_effect=ValueError('source revision')), \
                patch.object(audit, 'build') as compiler:
            with self.assertRaises(ValueError):
                audit.inspect(Path('/go'), Path('/rust'))
            compiler.assert_not_called()


if __name__ == '__main__':
    unittest.main()
