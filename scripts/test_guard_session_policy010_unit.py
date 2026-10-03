"""Check Guard policy observations reject effects and signatures after denial."""

import copy
import json
import unittest

from test_guard_dispatch010 import expected_effect
from test_guard_session_policy010 import (EMPTY_JOURNAL, EXPECTED_CASES, FIXTURE, SUITE,
                                          check_denied_reply, check_guard_result, digest_bytes)


class GuardSessionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIXTURE.read_text())
        self.intent = bytes.fromhex(self.fixture["input"]["envelope_hex"])
        self.denied = {
            "ok": False, "created": False, "committed": False,
            "state": "", "intent_digest": "", "effects": [],
            "result_hex": "", "signs": 0,
        }

    def test_suite_has_positive_and_post_open_revocation(self):
        suite = json.loads(SUITE.read_text())
        self.assertEqual(tuple((c["id"], c["policy_at_setup"], c["policy_after_open"],
                                c["expected_verdict"]) for c in suite["cases"]), EXPECTED_CASES)
        self.assertEqual(sum(c["policy_at_setup"] != c["policy_after_open"]
                             for c in suite["cases"]), 1)
        self.assertTrue(self.fixture["input"]["policy_allow"])
        self.assertEqual(EMPTY_JOURNAL, b"sage-execution-ledger|0.10.0\n")

    def test_allowed_result_requires_exactly_one_inert_effect(self):
        accepted = dict(self.denied, ok=True, created=True, committed=True,
                        state="EXECUTING", intent_digest=digest_bytes(self.intent),
                        effects=[expected_effect(self.intent, "old")])
        check_guard_result(accepted, True, self.intent)
        for change in ({"effects": []}, {"created": False}, {"signs": 1},
                       {"intent_digest": "other"}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                check_guard_result(dict(accepted, **change), True, self.intent)

    def test_denial_excludes_admission_effect_and_reply(self):
        check_guard_result(self.denied, False, self.intent)
        check_denied_reply(self.denied)
        for change in ({"ok": True}, {"created": True}, {"committed": True},
                       {"effects": [expected_effect(self.intent, "old")]},
                       {"result_hex": "00"}, {"signs": 1},
                       {"intent_digest": digest_bytes(self.intent)}):
            with self.subTest(change=change):
                observed = dict(self.denied, **change)
                with self.assertRaises(AssertionError):
                    check_guard_result(observed, False, self.intent)
                with self.assertRaises(AssertionError):
                    check_denied_reply(observed)

    def test_policy_change_does_not_change_signed_intent(self):
        configured = copy.deepcopy(self.fixture["input"])
        revoked = copy.deepcopy(configured)
        revoked["policy_allow"] = False
        self.assertEqual({key for key in configured if configured[key] != revoked[key]},
                         {"policy_allow"})
        self.assertEqual(revoked["envelope_hex"], configured["envelope_hex"])


if __name__ == "__main__":
    unittest.main()
