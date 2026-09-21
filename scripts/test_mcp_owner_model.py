from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from mcp_owner_model import State, step, invariant, explore
from check_mcp_catalog import ROOT


def run(*events):
    state = State()
    for event in events:
        after = step(state, event)
        invariant(state, event, after)
        state = after
    return state


class OwnerTests(unittest.TestCase):
    def test_close_before_reservation(self):
        s = run('setup_done', 'submit', 'close', 'reserve', 'admit', 'effect')
        self.assertEqual((s.ledger, s.effects, s.admitted), ('ABSENT', 0, False))

    def test_close_after_reservation(self):
        s = run('setup_done', 'submit', 'reserve', 'close', 'admit', 'effect')
        self.assertEqual((s.ledger, s.effects, s.admitted), ('RESERVED', 0, False))

    def test_admission_survives_close(self):
        s = run('setup_done', 'submit', 'reserve', 'admit', 'close', 'effect', 'finish', 'effect', 'respond')
        self.assertEqual((s.ledger, s.effects, s.published), ('COMPLETED', 1, False))

    def test_crash_prevents_redispatch(self):
        for effects in ((), ('effect',)):
            s = run('setup_done', 'submit', 'reserve', 'admit', *effects, 'crash', 'admit', 'effect', 'finish')
            self.assertEqual((s.ledger, s.effects), ('UNKNOWN', len(effects)))

    def test_protected_response_after_setup_deadline(self):
        s = run('setup_done', 'tick_31', 'submit', 'reserve', 'admit', 'effect', 'finish', 'respond')
        self.assertEqual((s.phase, s.published, s.deadline), ('READY', True, 41))

    def test_setup_exact_deadline_and_stale_callback(self):
        self.assertEqual(run('tick_30', 'setup_done').phase, 'CLOSED')
        s = run('setup_done', 'tick_31', 'submit')
        self.assertEqual(step(s, 'setup_done'), s)

    def test_protected_expiry_before_and_after_admission(self):
        prefix = ('setup_done', 'tick_30', 'submit', 'reserve')
        before = run(*prefix, 'tick_40', 'admit', 'effect')
        self.assertEqual((before.ledger, before.effects), ('RESERVED', 0))
        after = run(*prefix, 'admit', 'tick_40', 'effect', 'finish', 'respond')
        self.assertEqual((after.phase, after.ledger, after.published), ('CLOSED', 'COMPLETED', False))

    def test_session_expiry_and_rollback(self):
        s = run('setup_done', 'tick_59', 'submit', 'reserve', 'tick_60', 'admit', 'effect')
        self.assertEqual((s.phase, s.effects, s.deadline), ('CLOSED', 0, 69))
        self.assertEqual(run('setup_done', 'tick_31', 'tick_29').phase, 'CLOSED')

    def test_monitor_detects_invalid_successors(self):
        reserved = run('setup_done', 'submit', 'reserve', 'close')
        executing = run('setup_done', 'submit', 'reserve', 'admit')
        for before, event, after in [
            (reserved, 'admit', replace(reserved, admitted=True, ledger='EXECUTING')),
            (reserved, 'effect', replace(reserved, effects=1)),
            (reserved, 'close', replace(reserved, ledger='ABSENT')),
            (executing, 'close', replace(executing, admitted=False)),
            (executing, 'submit', replace(executing, deadline=99)),
        ]:
            with self.assertRaises(AssertionError):
                invariant(before, event, after)

    def test_exhaustive_reachability(self):
        result = explore()
        self.assertEqual(len(result['witnesses']), 4)
        # Replay the witness to verify publication occurs after the setup timer,
        # rather than merely observing an earlier response at a later clock value.
        events = result['witnesses']['response_after_setup_deadline']
        before = run(*events[:-1])
        self.assertEqual(events[-1], 'respond')
        self.assertFalse(before.published)
        self.assertGreater(before.now, 30)

    def test_real_cli_and_report_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'report'
            cmd = [sys.executable, '-B', str(ROOT / 'scripts/check_mcp_owner_model.py'), '--output', str(out)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr)
            raw = (out / 'report.json').read_bytes()
            report = json.loads(raw)
            self.assertEqual(report['status'], 'MODEL_CHECKED')
            self.assertFalse(report['actual_core_execution'])
            self.assertEqual(report['proposal_cases'], {'NOT_RUN': 71})
            self.assertEqual(report['lifecycle'], {'NOT_RUN': 37})
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(raw, (out / 'report.json').read_bytes())


if __name__ == '__main__':
    unittest.main()
