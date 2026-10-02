"""Keep the signed peer-binding controls distinct and fixed."""

import copy
import json
import unittest

from test_completion010 import ALICE, BOB, canonical, decode, encode
from test_signed_peer_binding010 import SUITE, changed_request, validate_suite


def sample():
    return canonical({
        "did": ALICE, "kid": ALICE + "#signing-1", "recipient": BOB,
        "payload": encode(canonical({"initDid": ALICE, "respDid": BOB})),
        "signature": "sample",
    })


class SignedPeerControls(unittest.TestCase):
    def test_fixed_outcomes(self):
        suite = json.loads(SUITE.read_text())
        validate_suite(suite)
        changed = copy.deepcopy(suite)
        changed["cases"][1]["expected_verdict"] = "ACCEPT"
        with self.assertRaises(AssertionError):
            validate_suite(changed)

    def test_semantic_sender_mismatch_is_validly_signed(self):
        output, key = changed_request(sample(), "sender")
        wire = json.loads(output)
        self.assertEqual(key, 2)
        self.assertEqual(wire["did"], BOB)
        self.assertEqual(wire["kid"], BOB + "#signing-1")
        self.assertEqual(json.loads(decode(wire["payload"]))["initDid"], ALICE)

    def test_expected_peer_mismatch_is_validly_signed(self):
        output, key = changed_request(sample(), "peer")
        wire = json.loads(output)
        self.assertEqual(key, 1)
        self.assertEqual(wire["recipient"], ALICE)
        self.assertEqual(json.loads(decode(wire["payload"]))["respDid"], ALICE)

    def test_other_key_signature_preserves_claimed_identity(self):
        output, key = changed_request(sample(), "other-key-signature")
        wire = json.loads(output)
        self.assertEqual(key, 2)
        self.assertEqual(wire["did"], ALICE)
        self.assertEqual(wire["kid"], ALICE + "#signing-1")


if __name__ == "__main__":
    unittest.main()
