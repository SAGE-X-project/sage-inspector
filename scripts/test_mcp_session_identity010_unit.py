"""Check fixture-only MCP identity variations retain independently valid signatures."""

import json
import unittest

from test_completion010 import ALICE, BOB, canonical, decode, encode, sign, verify
from test_mcp_session_identity010 import DOMAINS, signed_outer


class MCPSessionIdentityTests(unittest.TestCase):
    def test_signed_fields_still_disagree_with_session_identity(self):
        for phase, key in (("request", 1), ("response", 2)):
            did, peer = (ALICE, BOB) if key == 1 else (BOB, ALICE)
            original = {
                "did": did, "recipient": peer, "kid": did + "#signing-1",
                "role": "initiator" if key == 1 else "responder",
            }
            original["signature"] = encode(sign(DOMAINS[phase] + canonical(original), key))
            for mutation in ("did", "kid", "recipient", "role", "other-signer"):
                with self.subTest(phase=phase, mutation=mutation):
                    changed = json.loads(signed_outer(canonical(original), phase, mutation, key))
                    signature = decode(changed.pop("signature"))
                    actual_key = 3 - key if mutation == "other-signer" else key
                    verify(DOMAINS[phase] + canonical(changed), signature, actual_key)
                    if mutation == "did":
                        self.assertNotEqual(changed["did"], did)
                    elif mutation == "kid":
                        self.assertNotEqual(changed["kid"], did + "#signing-1")
                    elif mutation == "recipient":
                        self.assertNotEqual(changed["recipient"], peer)
                    elif mutation == "role":
                        self.assertNotEqual(changed["role"], original["role"])
                    else:
                        with self.assertRaises(AssertionError):
                            verify(DOMAINS[phase] + canonical(changed), signature, key)


if __name__ == "__main__":
    unittest.main()
