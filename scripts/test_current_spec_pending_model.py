"""Inert local state-machine controls for selected MSET and MOWN boundaries."""

import unittest

from mcp_setup_model import initial, step as setup_step
from mcp_owner_model import State as OwnerState, step as owner_step


class PendingModelTests(unittest.TestCase):
    def test_setup_output_barrier_and_deadline_equality(self):
        pending = setup_step(initial('client'), 'send_initialize')
        self.assertEqual(pending.phase, 'OUTPUT_PENDING')
        self.assertNotEqual(pending.phase, 'WAIT_INITIALIZE')
        after_send = setup_step(pending, 'send_ok')
        self.assertEqual(after_send.phase, 'WAIT_INITIALIZE')
        timed_out = setup_step(after_send, 'tick_30000')
        self.assertEqual(timed_out.phase, 'CLOSED')
        self.assertFalse(timed_out.admitted)

    def test_ready_owner_uses_operation_deadline(self):
        ready = OwnerState(phase='READY', operation='IDLE', now=31, deadline=30)
        protected = owner_step(ready, 'submit')
        self.assertEqual(protected.phase, 'READY')
        self.assertEqual(protected.operation, 'PROTECTED')
        self.assertEqual(protected.deadline, 41)

    def test_close_before_reservation_and_after_admission(self):
        before = OwnerState(phase='READY', operation='PROTECTED',
                            ledger='ABSENT', now=1, deadline=10)
        closed = owner_step(before, 'close')
        self.assertEqual(owner_step(closed, 'reserve'), closed)
        self.assertFalse(closed.admitted)
        self.assertEqual(closed.effects, 0)
        after = OwnerState(phase='READY', operation='PROTECTED',
                           ledger='EXECUTING', admitted=True,
                           now=1, deadline=10)
        closed_after = owner_step(after, 'close')
        self.assertTrue(closed_after.admitted)
        self.assertEqual(owner_step(closed_after, 'effect').effects, 1)
        self.assertEqual(owner_step(closed_after, 'admit').effects, 0)


if __name__ == '__main__':
    unittest.main()
