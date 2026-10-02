"""Check that the independent Gate observation controls remain exact."""

import copy
import json
import unittest

from test_strict_registry_identity010 import BASE, SUITE, request_for, validate_suite


class SuiteControls(unittest.TestCase):
    def test_fixed_cases_and_expected_journal_effects(self):
        suite = json.loads(SUITE.read_text())
        validate_suite(suite)
        changed = copy.deepcopy(suite)
        changed["cases"][1]["expected_journal_version"] = "2"
        with self.assertRaises(AssertionError):
            validate_suite(changed)

    def test_request_keeps_valid_source_control(self):
        suite = json.loads(SUITE.read_text())
        fixture = json.loads(BASE.read_text())
        base = next(c for c in fixture["cases"] if c["id"] == "kem-required")["steps"][0]["request"]
        case = next(c for c in suite["cases"] if c["id"] == "missing-key-fragment")
        request = request_for(case, base)
        self.assertTrue(request["source_ok"])
        self.assertTrue(request["clock_ok"])
        self.assertEqual(request["snapshot"], base["snapshot"])
        self.assertEqual(request["signing_url"], base["did"])


if __name__ == "__main__":
    unittest.main()
