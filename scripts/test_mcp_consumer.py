"""Artifact rejection units only; no sockets, host bypass or general tool execution."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import inspect_mcp_consumer as audit


class MCPConsumerTests(unittest.TestCase):
    def setUp(self):
        self.report = audit.strict_json(audit.REPORT.read_bytes())

    def case(self, scenario='allowed'):
        return copy.deepcopy(next(c for c in self.report['cases'] if c['id'].endswith('-' + scenario)))

    def rewrite(self, case, field, change, mode='client'):
        header = audit.LEDGER if field == 'ledger_hex' else audit.HEADER
        raw = bytes.fromhex(case[mode][field])
        rows = [json.loads(line) for line in raw[len(header):].splitlines()]
        change(rows)
        case[mode][field] = (header + b''.join(json.dumps(r, separators=(',', ':'),
            ensure_ascii=False).encode() + b'\n' for r in rows)).hex()

    def test_saved_external_observations(self):
        self.assertEqual(audit.check_report(self.report), 14)

    def test_every_direction_and_denial_is_required_once(self):
        for mutation in ('missing', 'duplicate', 'reordered'):
            r = copy.deepcopy(self.report)
            if mutation == 'missing': r['cases'].pop()
            elif mutation == 'duplicate': r['cases'][1] = r['cases'][0]
            else: r['cases'].reverse()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): audit.check_report(r)

    def test_scope_and_revision_cannot_be_promoted(self):
        for name in audit.SCOPE:
            r = copy.deepcopy(self.report); r['scope'][name] = 'PASS'
            with self.subTest(name=name), self.assertRaises(ValueError): audit.check_report(r)
        for name in ('go_revision', 'rust_revision', 'normative_source_revision', 'compiler_status', 'status'):
            r = copy.deepcopy(self.report); r[name] = 'unreviewed'
            with self.subTest(name=name), self.assertRaises(ValueError): audit.check_report(r)

    def test_pinned_inputs_fail_before_build(self):
        with tempfile.TemporaryDirectory() as d:
            changed = Path(d) / 'changed'; changed.write_bytes(b'unreviewed')
            for field in ('LOCK', 'RUST_LOCK'):
                with patch.object(audit, field, changed), patch.object(audit, 'build') as compiler:
                    with self.assertRaises(ValueError): audit.inspect(Path('/go'), Path('/rust'))
                    compiler.assert_not_called()
            with patch.object(audit, 'ADAPTERS', {'go': changed, 'rust': changed}), patch.object(audit, 'build') as compiler:
                with self.assertRaises(ValueError): audit.inspect(Path('/go'), Path('/rust'))
                compiler.assert_not_called()
        with patch.object(audit, 'check_source', side_effect=ValueError('source drift')), patch.object(audit, 'build') as compiler:
            with self.assertRaises(ValueError): audit.inspect(Path('/go'), Path('/rust'))
            compiler.assert_not_called()

    def test_one_actual_effect_and_integer_counts_required(self):
        for count in (0, 2, True):
            c = self.case(); c['server']['effects'] = count
            with self.subTest(count=count), self.assertRaises(ValueError): audit.check_case(c, 'allowed')
        for scenario in audit.DENIALS:
            c = self.case(scenario); c['server']['effects'] = 1
            with self.subTest(scenario=scenario), self.assertRaises(ValueError): audit.check_case(c, scenario)

    def test_denial_must_reach_its_declared_boundary(self):
        for scenario in audit.DENIALS:
            c = self.case(scenario); c['client']['stage'] = 'completed'
            with self.subTest(scenario=scenario), self.assertRaises(ValueError): audit.check_case(c, scenario)
        c = self.case('readiness-denied'); c['server']['prepare_denied'] = False
        with self.assertRaises(ValueError): audit.check_case(c, 'readiness-denied')

    def test_one_signing_attempt_and_exact_fence(self):
        for scenario in ('allowed', 'capture-denied', 'signing-denied'):
            for count in (0, 2, True):
                c = self.case(scenario); c['client']['sign_calls'] = count
                with self.subTest(scenario=scenario, count=count), self.assertRaises(ValueError): audit.check_case(c, scenario)
            c = self.case(scenario); c['client']['fence_hex'] = audit.FENCE.hex()
            with self.subTest(scenario=scenario), self.assertRaises(ValueError): audit.check_case(c, scenario)

    def test_failed_signing_never_produces_a_client(self):
        c = self.case('signing-denied'); c['client']['journal_hex'] = audit.HEADER.hex()
        with self.assertRaises(ValueError): audit.check_case(c, 'signing-denied')

    def test_transfer_has_no_prior_transport_and_keeps_journal(self):
        c = self.case()
        self.rewrite(c, 'before_transfer_hex', lambda rows: rows.append(
            {'kind': 'send', 'id': '00000000-0000-4000-8000-000000000099', 'at': 460000, 'intent_hex': '', 'result_hex': ''}))
        with self.assertRaises(ValueError): audit.check_case(c, 'allowed')
        c = self.case(); c['client']['journal_hex'] = audit.HEADER.hex()
        with self.assertRaises(ValueError): audit.check_case(c, 'allowed')

    def test_capture_mismatch_does_not_send(self):
        c = self.case('capture-denied')
        c['client']['journal_hex'] += audit.canonical({'kind': 'send', 'id': '00000000-0000-4000-8000-000000000099',
            'at': 461000, 'intent_hex': '', 'result_hex': ''}).hex() + '0a'
        with self.assertRaises(ValueError): audit.check_case(c, 'capture-denied')
        c = self.case('capture-denied'); c['client']['owned_capture_digest'] = '0' * 64
        with self.assertRaises(ValueError): audit.check_case(c, 'capture-denied')

    def test_valid_signature_does_not_replace_original_or_policy(self):
        for field in ('original_digest', 'policy_digest', 'manifest_digest'):
            c = self.case(); body = audit.strict_json(bytes.fromhex(c['client']['issuance_body_hex']))
            body[field] = '0' * 64; raw_body = audit.canonical(body)
            signature = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32).sign(
                b'sage-execution-intent|0.10.0\0' + raw_body)
            envelope = audit.canonical({'intent': body, 'proof': base64.urlsafe_b64encode(signature).rstrip(b'=').decode()})
            self.assertEqual(audit.signed(envelope, 'intent', 1), body)
            c['client']['issuance_body_hex'] = raw_body.hex()
            c['client']['fence_hex'] = (audit.FENCE + audit.sha(raw_body).encode() + b'\n').hex()
            for field_name in ('journal_hex', 'before_transfer_hex'):
                self.rewrite(c, field_name, lambda rows: rows[0].update(intent_hex=envelope.hex()))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'independent original'):
                audit.check_case(c, 'allowed')

    def test_invalid_signed_result_is_rejected(self):
        c = self.case()
        def corrupt(rows):
            env = audit.strict_json(bytes.fromhex(rows[-1]['result_hex']))
            env['result']['output'] = {'ok': False}
            rows[-1]['result_hex'] = audit.canonical(env).hex()
        self.rewrite(c, 'journal_hex', corrupt)
        with self.assertRaises(InvalidSignature): audit.check_case(c, 'allowed')

    def test_valid_signed_result_still_requires_binding(self):
        c = self.case()
        def resign(rows):
            env = audit.strict_json(bytes.fromhex(rows[-1]['result_hex']))
            env['result']['intent_digest'] = '0' * 64
            proof = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32).sign(
                b'sage-tool-result|0.10.0\0' + audit.canonical(env['result']))
            env['proof'] = base64.urlsafe_b64encode(proof).rstrip(b'=').decode()
            rows[-1]['result_hex'] = audit.canonical(env).hex()
        self.rewrite(c, 'journal_hex', resign)
        with self.assertRaisesRegex(ValueError, 'signed result binding'): audit.check_case(c, 'allowed')

    def test_retry_delay_and_attempt_consumption(self):
        for index, change in [(1, {'at': 460999}), (2, {'id': '00000000-0000-4000-8000-000000000099'}), (0, {'at': False})]:
            c = self.case(); self.rewrite(c, 'journal_hex', lambda rows: rows[index].update(change))
            with self.subTest(index=index), self.assertRaises(ValueError): audit.check_case(c, 'allowed')

    def test_ledger_requires_one_reservation_and_exact_result(self):
        for mutation in ('duplicate', 'missing-result', 'missing-reservation'):
            c = self.case()
            def change(rows):
                if mutation == 'duplicate': rows.append(rows[-1])
                elif mutation == 'missing-result': rows[-1]['result_hex'] = ''
                else: rows.pop(0)
            self.rewrite(c, 'ledger_hex', change, 'server')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): audit.check_case(c, 'allowed')

    def test_observations_cannot_reuse_issuance_identity(self):
        r = copy.deepcopy(self.report)
        duplicate = copy.deepcopy(r['cases'][0]); duplicate['id'] = r['cases'][1]['id']; r['cases'][1] = duplicate
        with self.assertRaisesRegex(ValueError, 'fresh issuance'): audit.check_report(r)

    def test_closed_json_and_bounded_hex(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError): audit.strict_json(raw)
        for raw in ('GG', '0', 'aa' * 100001):
            with self.assertRaises(ValueError): audit.decode(raw)


if __name__ == '__main__':
    unittest.main()
