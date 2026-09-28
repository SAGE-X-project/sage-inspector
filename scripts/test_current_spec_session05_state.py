"""Stateful SESSION-05 projections require exact replay verdicts and counters."""

import unittest

from current_spec_catalog import ROOT
from run_current_spec_session05_state import project


def row(verdict, opens):
    return {'verdict': verdict, 'effects': {'core_open_success': opens,
            'core_seal_success': 0, 'core_close_calls': 0}}


class Session05StateTests(unittest.TestCase):
    def test_reordered_records_and_duplicate_are_partial_only(self):
        result = project(ROOT, 'SESSION-05-P', [row('ACCEPT', 0),
            row('ACCEPT', 1), row('ACCEPT', 2), row('ACCEPT', 3),
            row('REJECT', 3)])
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(result['actual']['output']['accepted_sequences'],
                         [999, 0, 256])

    def test_bad_tag_must_not_consume_the_sequence(self):
        result = project(ROOT, 'SESSION-05-N02', [row('ACCEPT', 0),
            row('REJECT', 0), row('ACCEPT', 1)])
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(project(ROOT, 'SESSION-05-N02', [row('ACCEPT', 0),
            row('REJECT', 0), row('REJECT', 0)])['status'], 'FAIL')

    def test_effect_counter_cannot_advance_on_rejected_record(self):
        with self.assertRaises(ValueError):
            project(ROOT, 'SESSION-05-N03', [row('ACCEPT', 0),
                row('ACCEPT', 1), row('ACCEPT', 2), row('REJECT', 3)])


if __name__ == '__main__':
    unittest.main()
