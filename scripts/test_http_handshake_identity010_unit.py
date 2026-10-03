"""Check independent signatures and semantic identity gaps in the fixed HTTP suite."""

import base64
import json
import unittest

from test_completion010 import ALICE, BOB, canonical, verify
from test_http_handshake_identity010 import altered
from test_http_session010 import b64, content_digest, field, headers, resign, signature_base


class HTTPHandshakeIdentityTests(unittest.TestCase):
    def message(self, key, request=None):
        did = ALICE if key == 1 else BOB
        m = {
            "method": "POST" if request is None else "",
            "target": "https://agent.example/messages" if request is None else "",
            "authority": "agent.example" if request is None else "",
            "status": 0 if request is None else 200,
            "body": b64(canonical({"did": did, "kid": did + "#signing-1"})),
            "headers": [
                ["content-type", "application/json"],
                ["x-sage-did", did],
                ["x-sage-version", "0.10.0"],
                ["signature-input", 'sig1=("@method");keyid="' + did + '#signing-1";alg="ed25519";created=100;expires=400;nonce="n";tag="sage-0.10.0"'],
            ],
        }
        field(m, "content-digest", content_digest(m))
        resign(m, key, request)
        return m

    def test_valid_signatures_cannot_replace_identity_checks(self):
        request = self.message(1)
        for key, original, context in ((1, request, None), (2, self.message(2, request), request)):
            for mutation in ("did", "wrong-keyid", "wrong-alg", "other-signer"):
                with self.subTest(key=key, mutation=mutation):
                    changed = altered(original, mutation, key, context)
                    h = headers(changed)
                    body = json.loads(base64.b64decode(changed["body"], validate=True))
                    signature = base64.b64decode(h["signature"][6:-1], validate=True)
                    actual_key = 3 - key if mutation == "other-signer" else key
                    verify(signature_base(changed, context), signature, actual_key)
                    if mutation == "did":
                        self.assertNotEqual(h["x-sage-did"], body["did"])
                    elif mutation == "wrong-keyid":
                        self.assertNotIn(body["kid"] + '"', h["signature-input"])
                    elif mutation == "wrong-alg":
                        self.assertIn('alg="rsa-pss-sha512"', h["signature-input"])
                    else:
                        with self.assertRaises(AssertionError):
                            verify(signature_base(changed, context), signature, key)


if __name__ == "__main__":
    unittest.main()
