"""Stateful SESSION-05 projections require exact replay verdicts and counters."""

import unittest

from current_spec_catalog import ROOT, load
from run_current_spec_session05_state import project, requests


def responses(ident, verdicts):
    _, queries = requests(ROOT, ident)
    records = load((ROOT / 'vectors/0.10.0/session-records.json').read_bytes())['cases']
    known = {row['input']['record_hex']: row['expected']['output']['plaintext_hex']
             for row in records if row['operation'] == 'sage.session.record.open'
             and row['expected']['verdict'] == 'ACCEPT'}
    result = [{'verdict': 'ACCEPT',
               'output': {'session_id': '7_DwdcM8kMwneSBrBd-9Yg'},
               'effects': {'core_open_success': 0,
                           'core_seal_success': 0, 'core_close_calls': 0}}]
    accepted = 0
    for query, verdict in zip(queries[1:], verdicts):
        if verdict == 'ACCEPT':
            accepted += 1
            output = {'plaintext_hex': known[query['input']['record_hex']]}
        else:
            output = {}
        result.append({'verdict': verdict, 'output': output,
                       'effects': {'core_open_success': accepted,
                                   'core_seal_success': 0, 'core_close_calls': 0}})
    return result


class Session05StateTests(unittest.TestCase):
    def test_reordered_records_and_duplicate_are_partial_only(self):
        result = project(ROOT, 'SESSION-05-P', responses('SESSION-05-P',
            ['ACCEPT', 'ACCEPT', 'ACCEPT', 'REJECT']))
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(result['actual']['output']['accepted_sequences'],
                         [999, 0, 256])

    def test_bad_tag_must_not_consume_the_sequence(self):
        result = project(ROOT, 'SESSION-05-N02', responses('SESSION-05-N02',
            ['REJECT', 'ACCEPT']))
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(project(ROOT, 'SESSION-05-N02', responses('SESSION-05-N02',
            ['REJECT', 'REJECT']))['status'], 'FAIL')

    def test_effect_counter_cannot_advance_on_rejected_record(self):
        with self.assertRaises(ValueError):
            rows = responses('SESSION-05-N03', ['ACCEPT', 'ACCEPT', 'REJECT'])
            rows[-1]['effects']['core_open_success'] = 3
            project(ROOT, 'SESSION-05-N03', rows)


if __name__ == '__main__':
    unittest.main()
