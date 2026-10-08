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
import inspect_hop_execution as audit


class HopExecutionTests(unittest.TestCase):
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
        child['fence_hex'] = (audit.root_consumer.FENCE + audit.sha(raw).encode() + b'\n').hex()
        child['signed_intent_hex'] = envelope.hex()
        child['journal_hex'] = (audit.HEADER + audit.canonical({'kind': 'open', 'id': '', 'at': 0,
            'intent_hex': envelope.hex(), 'result_hex': ''}) + b'\n').hex()
        return envelope

    def test_saved_observations(self):
        self.assertEqual(audit.check_report(self.report), 16)

    def test_all_three_core_combinations_and_refusals_required(self):
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
        for scenario in ('allowed', 'signing-denied', 'leaf-readiness-denied'):
            case, child = self.child(scenario); child['token_reuse_denied'] = False
            with self.subTest(scenario=scenario), self.assertRaises(ValueError): audit.check_case(case, scenario)

    def test_one_child_sign_and_exact_fence(self):
        for scenario in ('allowed', 'signing-denied', 'leaf-readiness-denied'):
            for value in (0, 2, True):
                case, child = self.child(scenario); child['sign_calls'] = value
                with self.subTest(scenario=scenario, value=value), self.assertRaises(ValueError): audit.check_case(case, scenario)
            case, child = self.child(scenario); child['fence_hex'] = audit.root_consumer.FENCE.hex()
            with self.assertRaises(ValueError): audit.check_case(case, scenario)

    def test_own_denial_reaches_declared_boundary(self):
        for scenario in audit.issuance.DENIALS:
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

    def test_extra_child_transmission_rejected(self):
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
        case, child = self.child(); child['status'] = 'issued'
        with self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_distinct_issuance_across_observations(self):
        value = copy.deepcopy(self.report)
        duplicate = copy.deepcopy(value['cases'][0]); duplicate['id'] = value['cases'][1]['id']
        value['cases'][1] = duplicate
        with self.assertRaisesRegex(ValueError, 'distinct root and child'): audit.check_report(value)



    def journal(self, child):
        return audit.root_consumer.events(bytes.fromhex(child['journal_hex']))

    def write_journal(self, child, rows):
        child['journal_hex'] = (audit.HEADER + b''.join(audit.canonical(row) + b'\n' for row in rows)).hex()

    def change_result(self, case, owner, seed, change):
        record = case['client'] if owner == 'root' else case['server']['child']
        rows = audit.root_events(bytes.fromhex(record['journal_hex']))
        envelope = audit.strict_json(bytes.fromhex(rows[-1]['result_hex']))
        change(envelope['result'])
        proof = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).sign(
            b'sage-tool-result|0.10.0\0' + audit.canonical(envelope['result']))
        envelope['proof'] = base64.urlsafe_b64encode(proof).rstrip(b'=').decode()
        raw = audit.canonical(envelope)
        audit.signed(raw, 'result', seed)
        rows[-1]['result_hex'] = raw.hex(); self.write_journal(record, rows)
        ledger_record = case['server'] if owner == 'root' else case['leaf']
        ledger = bytes.fromhex(ledger_record['ledger_hex'])
        entries = [audit.strict_json(line) for line in ledger[len(audit.LEDGER):].splitlines()]
        entries[-1]['result_hex'] = raw.hex()
        ledger_record['ledger_hex'] = (audit.LEDGER + b''.join(audit.canonical(row) + b'\n' for row in entries)).hex()
        return raw

    def test_root_consumes_exact_child_outcome(self):
        for scenario in ('allowed', *audit.issuance.DENIALS, 'leaf-readiness-denied'):
            case = self.case(scenario); case['client']['consumed_output_hex'] = audit.canonical({'ok': True}).hex()
            with self.subTest(scenario=scenario), self.assertRaises(ValueError): audit.check_case(case, scenario)

    def test_signed_root_cannot_report_refused_child_as_completed(self):
        for scenario in (*audit.issuance.DENIALS, 'leaf-readiness-denied'):
            case = self.case(scenario)
            false_output = {'child_status': 'completed', 'output': {'ok': True}}
            self.change_result(case, 'root', 2, lambda r: r.update(output=false_output))
            case['client']['consumed_output_hex'] = audit.canonical(false_output).hex()
            with self.subTest(scenario=scenario), self.assertRaises(ValueError): audit.check_case(case, scenario)

    def test_root_result_time_bound_to_actual_child_progress(self):
        case = self.case(); ticks = case['server']['child']['ticks']
        self.change_result(case, 'root', 2, lambda r: r.update(created=460+ticks+1, expires=760+ticks+1))
        with self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_child_result_still_requires_exact_execution_bindings(self):
        for key, value in {'intent_digest': '0'*64, 'issuer': audit.BOB, 'recipient': audit.ALICE,
                           'created': 461, 'output': {'ok': False}, 'status': 'failed'}.items():
            case = self.case(); self.change_result(case, 'child', 1, lambda r: r.update({key:value}))
            with self.subTest(key=key), self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_child_native_delivery_is_exactly_once(self):
        for field, values in {'delivery_count': [0, 2, True], 'delivery_output_hex': ['', '00'],
                              'ticks': [0, 11, True], 'connection_status': ['DENIED', 'NOT_ATTEMPTED']}.items():
            for value in values:
                case, child = self.child(); child[field] = value
                with self.subTest(field=field,value=value), self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_one_leaf_effect_and_actual_connection(self):
        for field in ('effects', 'connections'):
            for value in (0, 2, True):
                case = self.case(); case['leaf'][field] = value
                with self.subTest(field=field,value=value), self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_leaf_requires_exact_parent_context(self):
        case = self.case(); case['leaf']['observed_parent_hex'] = '00'
        with self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_refusal_before_leaf_reservation(self):
        for scenario in (*audit.issuance.DENIALS, 'leaf-readiness-denied'):
            for field, value in {'effects': 1, 'ledger_hex': (audit.LEDGER+b'{}\n').hex(),
                                 'observed_parent_hex': '00'}.items():
                case = self.case(scenario); case['leaf'][field] = value
                with self.subTest(scenario=scenario,field=field), self.assertRaises(ValueError): audit.check_case(case, scenario)

    def test_readiness_denial_reaches_real_leaf_prepare(self):
        for field, value in {'connections': 0, 'prepare_denied': False}.items():
            case = self.case('leaf-readiness-denied'); case['leaf'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): audit.check_case(case, 'leaf-readiness-denied')
        case, child = self.child('leaf-readiness-denied'); child['journal_hex'] += (audit.canonical(
            {'kind':'send','id':'00000000-0000-4000-8000-000000000099','at':461000,'intent_hex':'','result_hex':''})+b'\n').hex()
        with self.assertRaises(ValueError): audit.check_case(case, 'leaf-readiness-denied')

    def test_child_handoff_is_original_append_only_journal(self):
        for mutation in ('empty', 'transport-before-transfer', 'replace-open'):
            case, child = self.child(); rows = self.journal(child)
            if mutation == 'empty': child['before_transfer_hex'] = audit.HEADER.hex()
            elif mutation == 'transport-before-transfer': child['before_transfer_hex'] = child['journal_hex']
            else: rows[0]['intent_hex'] = '00'; self.write_journal(child, rows)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_child_attempt_clock_and_terminal_identity(self):
        for mutation in ('cadence', 'terminal-id', 'duplicate-terminal', 'root-id'):
            case, child = self.child(); rows = self.journal(child)
            if mutation == 'cadence': rows[1]['at'] += 1
            elif mutation == 'terminal-id': rows[-1]['id'] = '00000000-0000-4000-8000-000000000099'
            elif mutation == 'duplicate-terminal': rows.append(rows[-1])
            else: rows[1]['id'] = audit.root_events(bytes.fromhex(case['client']['journal_hex']))[1]['id']
            self.write_journal(child, rows)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_leaf_ledger_cannot_omit_or_duplicate_execution(self):
        for mutation in ('missing', 'duplicate', 'wrong-intent'):
            case = self.case(); raw = bytes.fromhex(case['leaf']['ledger_hex'])
            rows = [audit.strict_json(line) for line in raw[len(audit.LEDGER):].splitlines()]
            if mutation == 'missing': rows.pop(1)
            elif mutation == 'duplicate': rows.insert(1, rows[1])
            else: rows[1]['intent_hex'] = '00'
            case['leaf']['ledger_hex'] = (audit.LEDGER+b''.join(audit.canonical(row)+b'\n' for row in rows)).hex()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_bootstrap_recovery_needs_actual_authenticated_exchange(self):
        for prefix in ('root', 'child'):
            case = self.case(); case['server']['bootstrap'][prefix+'_replay_hex'] = b'sage-replay-denials|0.10.0\n'.hex()
            with self.subTest(prefix=prefix), self.assertRaises(ValueError): audit.check_case(case, 'allowed')
            case = self.case(); record = case['server']['bootstrap']; raw=bytes.fromhex(record[prefix+'_replay_hex'])
            header=b'sage-replay-denials|0.10.0\n'; row=audit.strict_json(raw[len(header):]); row['nonce']='A'*22
            record[prefix+'_replay_hex']=(header+audit.canonical(row)+b'\n').hex()
            with self.subTest(prefix=prefix), self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_bootstrap_invalid_outer_signature(self):
        case = self.case(); record = case['server']['bootstrap']
        wire = audit.strict_json(bytes.fromhex(record['root_request_hex'])); wire['signature']='A'*86
        record['root_request_hex']=audit.canonical(wire).hex()
        with self.assertRaises(InvalidSignature): audit.check_case(case, 'allowed')

    def test_valid_bootstrap_signature_cannot_change_signing_role(self):
        case = self.case(); record = case['server']['bootstrap']
        wire=audit.strict_json(bytes.fromhex(record['child_request_hex'])); del wire['signature']
        wire['kid']=audit.BOB+'#kem-1'
        proof=Ed25519PrivateKey.from_private_bytes(bytes([2])*32).sign(b'sage-wire-request|0.10.0\n'+audit.canonical(wire))
        wire['signature']=base64.urlsafe_b64encode(proof).rstrip(b'=').decode()
        record['child_request_hex']=audit.canonical(wire).hex()
        with self.assertRaises(ValueError): audit.check_case(case, 'allowed')

    def test_closed_leaf_and_bootstrap_records(self):
        for owner in ('leaf', 'bootstrap'):
            case=self.case(); record=case['leaf'] if owner=='leaf' else case['server']['bootstrap']
            record['trusted']=True
            with self.subTest(owner=owner), self.assertRaises(ValueError): audit.check_case(case, 'allowed')


if __name__ == '__main__':
    unittest.main()
