"""Artifact-only refusal units; no sockets or attacker programs."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import inspect_hop_issuance as audit


class HopIssuanceTests(unittest.TestCase):
    def setUp(self):
        self.report = audit.strict_json(audit.REPORT.read_bytes())

    def case(self, scenario='allowed'):
        return copy.deepcopy(next(c for c in self.report['cases'] if c['id'].endswith('-' + scenario)))

    def child(self, scenario='allowed'):
        case = self.case(scenario)
        return case, case['server']['child']

    def resign(self, child, change):
        body = audit.strict_json(bytes.fromhex(child['issuance_body_hex']))
        change(body)
        raw = audit.canonical(body)
        proof = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32).sign(
            b'sage-execution-intent|0.10.0\0' + raw)
        envelope = audit.canonical({'intent': body, 'proof': base64.urlsafe_b64encode(proof).rstrip(b'=').decode()})
        child['issuance_body_hex'] = raw.hex()
        child['fence_hex'] = (audit.FENCE + audit.sha(raw).encode() + b'\n').hex()
        child['signed_intent_hex'] = envelope.hex()
        child['journal_hex'] = (audit.HEADER + audit.canonical({'kind': 'open', 'id': '', 'at': 0,
            'intent_hex': envelope.hex(), 'result_hex': ''}) + b'\n').hex()
        return envelope

    def test_saved_observations(self):
        self.assertEqual(audit.check_report(self.report), 10)

    def test_all_directions_and_own_denials_required(self):
        for mutation in ('missing', 'duplicate', 'order'):
            value = copy.deepcopy(self.report)
            if mutation == 'missing': value['cases'].pop()
            elif mutation == 'duplicate': value['cases'][1] = value['cases'][0]
            else: value['cases'].reverse()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): audit.check_report(value)

    def test_scope_and_provenance_cannot_be_promoted(self):
        for key in audit.SCOPE:
            value = copy.deepcopy(self.report); value['scope'][key] = 'PASS'
            with self.subTest(key=key), self.assertRaises(ValueError): audit.check_report(value)
        for key in ('go_revision', 'rust_revision', 'normative_source_revision', 'compiler_status', 'status'):
            value = copy.deepcopy(self.report); value[key] = 'unreviewed'
            with self.subTest(key=key), self.assertRaises(ValueError): audit.check_report(value)

    def test_drift_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as d:
            changed = Path(d) / 'changed'; changed.write_bytes(b'changed')
            with patch.object(audit, 'ADAPTERS', {'go': changed, 'rust': changed}), patch.object(audit, 'build') as compiler:
                with self.assertRaises(ValueError): audit.inspect(Path('/go'), Path('/rust'))
                compiler.assert_not_called()
        with patch.object(audit, 'check_source', side_effect=ValueError('revision')), patch.object(audit, 'build') as compiler:
            with self.assertRaises(ValueError): audit.inspect(Path('/go'), Path('/rust'))
            compiler.assert_not_called()

    def test_source_rechecked_after_execution(self):
        with patch.object(audit, 'check_source', side_effect=lambda p, _: p), \
                patch.object(audit, 'sources_at', side_effect=[audit.SOURCE_SHA256, ValueError('late drift')]) as source, \
                patch.object(audit, 'build', return_value={}), patch.object(audit, 'observe', return_value={}):
            with self.assertRaisesRegex(ValueError, 'late drift'): audit.inspect(Path('/go'), Path('/rust'))
            self.assertEqual(source.call_count, 2)

    def test_parent_must_be_exact_actual_inbound(self):
        case, child = self.child(); child['incoming_hex'] = audit.HEADER.hex()
        with self.assertRaisesRegex(ValueError, 'exact admitted inbound'): audit.check_case(case, 'allowed')

    def test_finished_parent_must_be_denied(self):
        for value in (False, 1, None):
            case, child = self.child(); child['parent_after_finish_denied'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_own_approval_is_one_use(self):
        for scenario in ('allowed', 'signing-denied'):
            case, child = self.child(scenario); child['token_reuse_denied'] = False
            with self.subTest(scenario=scenario), self.assertRaises(ValueError): audit.check_case(case, scenario)

    def test_one_child_sign_and_exact_fence(self):
        for scenario in ('allowed', 'signing-denied'):
            for value in (0, 2, True):
                case, child = self.child(scenario); child['sign_calls'] = value
                with self.subTest(scenario=scenario, value=value), self.assertRaises(ValueError): audit.check_case(case, scenario)
            case, child = self.child(scenario); child['fence_hex'] = audit.FENCE.hex()
            with self.assertRaises(ValueError): audit.check_case(case, scenario)

    def test_own_denial_reaches_declared_boundary(self):
        for scenario in audit.DENIALS:
            case, child = self.child(scenario); child['stage'] = 'issued'
            with self.subTest(scenario=scenario), self.assertRaises(ValueError): audit.check_case(case, scenario)

    def test_denied_policy_and_measurement_never_sign(self):
        for scenario in ('policy-denied', 'measurement-denied'):
            for field in ('journal_hex', 'fence_hex', 'issuance_body_hex', 'signed_intent_hex'):
                case, child = self.child(scenario); child[field] = '00'
                with self.subTest(scenario=scenario, field=field), self.assertRaises(ValueError): audit.check_case(case, scenario)

    def test_failed_signing_keeps_fence_without_client(self):
        for field in ('journal_hex', 'signed_intent_hex'):
            case, child = self.child('signing-denied'); child[field] = '00'
            with self.subTest(field=field), self.assertRaises(ValueError): audit.check_case(case, 'signing-denied')

    def test_valid_signature_still_requires_independent_child_bindings(self):
        changes = {'parent_call_id': None, 'issuer': audit.ALICE, 'recipient': audit.BOB,
                   'original_digest': '0'*64, 'policy_digest': '0'*64, 'manifest_digest': '0'*64,
                   'request_id': '00000000-0000-4000-8000-000000000002',
                   'arguments': {'path': 'other.txt'}, 'keyid': audit.ALICE + '#signing-1',
                   'expires': 761, 'unexpected': 'field'}
        for key, value in changes.items():
            case, child = self.child()
            envelope = self.resign(child, lambda body: body.update({key: value}))
            audit.signed(envelope, 'intent', 2)
            with self.subTest(key=key), self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_child_cannot_reuse_parent_call_identity(self):
        case, child = self.child()
        parent = audit.strict_json(bytes.fromhex(child['incoming_hex']))['intent']
        self.resign(child, lambda body: body.update(call_id=parent['call_id']))
        with self.assertRaisesRegex(ValueError, 'fresh child identity'): audit.check_case(case, 'allowed')

    def test_invalid_child_proof_rejected(self):
        case, child = self.child()
        envelope = audit.strict_json(bytes.fromhex(child['signed_intent_hex'])); envelope['proof'] = 'A'*86
        child['signed_intent_hex'] = audit.canonical(envelope).hex()
        with self.assertRaises(InvalidSignature): audit.check_case(case, 'allowed')

    def test_child_has_no_transmission_or_result(self):
        case, child = self.child()
        child['journal_hex'] += (audit.canonical({'kind': 'send', 'id': '00000000-0000-4000-8000-000000000099',
            'at': 460000, 'intent_hex': '', 'result_hex': ''}) + b'\n').hex()
        with self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_one_root_execution_and_signed_terminal(self):
        case = self.case(); case['server']['effects'] = 2
        with self.assertRaises(ValueError): audit.check_case(case, 'allowed')
        case = self.case(); case['client']['journal_hex'] = audit.HEADER.hex()
        with self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_closed_child_artifact(self):
        case, child = self.child(); child['trusted'] = True
        with self.assertRaises(ValueError): audit.check_case(case, 'allowed')
        case, child = self.child(); child['status'] = 'completed'
        with self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_distinct_issuance_across_observations(self):
        value = copy.deepcopy(self.report)
        duplicate = copy.deepcopy(value['cases'][0]); duplicate['id'] = value['cases'][1]['id']
        value['cases'][1] = duplicate
        with self.assertRaisesRegex(ValueError, 'distinct root and child'): audit.check_report(value)


if __name__ == '__main__':
    unittest.main()
