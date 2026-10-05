"""Guard signed result observations and reject evidence-scope promotion."""

import base64
import copy
import json
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from inspect_captured_client_results import (ROOT, canonical, check_report,
                                              check_replies, fixture_commands,
                                              reply, sha)


class CapturedClientResultTests(unittest.TestCase):
    def report(self):
        return json.loads((ROOT / 'docs/evidence/captured-client-results.json').read_text())

    def test_result_signatures_and_binding(self):
        command, results, _, _ = fixture_commands()
        public = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(command['public_key_hex']))
        for name in ('completed', 'pending', 'wrong-intent'):
            envelope = json.loads(bytes.fromhex(results[name]))
            proof = base64.urlsafe_b64decode(envelope['proof'] + '==')
            public.verify(proof, b'sage-tool-result|0.10.0\0' +
                          canonical(envelope['result']))
            self.assertEqual(envelope['result']['intent_digest'],
                '0' * 64 if name == 'wrong-intent' else
                sha(bytes.fromhex(command['input']['envelope_hex'])))
        broken = json.loads(bytes.fromhex(results['invalid-proof']))
        with self.assertRaises(InvalidSignature):
            public.verify(base64.urlsafe_b64decode(broken['proof'] + '=='),
                          b'sage-tool-result|0.10.0\0' +
                          canonical(broken['result']))

    def test_report_keeps_runtime_scope(self):
        self.assertEqual(check_report(self.report()), 10)
        for key in ('deployed_host', 'full_protocol_conformance'):
            changed = copy.deepcopy(self.report())
            changed[key] = 'PASS'
            with self.assertRaisesRegex(ValueError, 'scope or provenance'):
                check_report(changed)

    def test_unbound_result_cannot_be_reclassified(self):
        changed = self.report()
        changed['cases'][1]['output_releases'] = 1
        with self.assertRaisesRegex(ValueError, 'case verdicts or journal bytes'):
            check_report(changed)

    def test_cross_language_restart_cannot_redeliver(self):
        changed = self.report()
        changed['cases'][-1]['output_releases'] = 1
        with self.assertRaisesRegex(ValueError, 'case verdicts or journal bytes'):
            check_report(changed)

    def test_runtime_reply_cannot_release_unexpected_output(self):
        with self.assertRaisesRegex(ValueError, 'observations differ'):
            check_replies([reply(ok=False, output_hex='7b7d')], [reply(ok=False)])

    def test_runtime_reply_cannot_hide_an_extra_handoff(self):
        with self.assertRaisesRegex(ValueError, 'observations differ'):
            check_replies([reply(handoffs=1)], [reply()])


if __name__ == '__main__':
    unittest.main()
