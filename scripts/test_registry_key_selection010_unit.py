"""Check independent key-selection expectations and request controls."""

import copy
import json
import unittest

from test_registry_key_selection010 import BASE, SUITE, request_for, validate_suite


class KeySelectionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = json.loads(SUITE.read_text())
        fixture = json.loads(BASE.read_text())
        cls.base = next(c for c in fixture["cases"] if c["id"] == "kem-required")["steps"][0]["request"]

    def test_fixed_case_order_and_results(self):
        validate_suite(self.suite)
        changed = copy.deepcopy(self.suite)
        changed["cases"][1]["expected_journal_version"] = "0"
        with self.assertRaises(AssertionError):
            validate_suite(changed)
        changed = copy.deepcopy(self.suite)
        changed["cases"][1]["id"] = changed["cases"][0]["id"]
        with self.assertRaises(AssertionError):
            validate_suite(changed)

    def test_revoked_key_has_an_eligible_alternative(self):
        case = next(c for c in self.suite["cases"] if c["id"] == "revoked-signer-no-fallback")
        request = request_for(case, self.base)
        keys = {k["name"]: k for k in request["snapshot"]["keys"]}
        self.assertEqual(keys["signing-1"]["state"], "revoked")
        self.assertEqual(keys["signing-2"]["state"], "accepted")
        self.assertEqual(keys["signing-2"]["alg"], "ed25519")
        self.assertTrue(request["source_ok"])
        self.assertEqual(self.base["snapshot"]["keys"][1]["state"], "accepted")

    def test_expiry_is_on_the_trusted_boundary(self):
        case = next(c for c in self.suite["cases"] if c["id"] == "expired-signer-no-fallback")
        request = request_for(case, self.base)
        selected = next(k for k in request["snapshot"]["keys"] if k["name"] == "signing-1")
        self.assertEqual(selected["expires"], request["times"][-1]["unix"])
        self.assertTrue(any(k["name"] == "signing-2" and k["state"] == "accepted"
                            for k in request["snapshot"]["keys"]))

    def test_kem_denial_keeps_usable_signer(self):
        case = next(c for c in self.suite["cases"] if c["id"] == "missing-kem-cannot-establish-session")
        request = request_for(case, self.base)
        keys = {k["name"]: k for k in request["snapshot"]["keys"]}
        self.assertTrue(request["require_kem"])
        self.assertEqual(keys["kem-1"]["state"], "revoked")
        self.assertEqual(keys["signing-1"]["state"], "accepted")


if __name__ == "__main__":
    unittest.main()
