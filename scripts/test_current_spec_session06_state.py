"""Closed record sessions must release no plaintext or new record."""

import unittest

from current_spec_catalog import ROOT, load
from run_current_spec_session06_state import project, requests


def responses():
    _, queries = requests(ROOT)
    records = load((ROOT / 'vectors/0.10.0/session-records.json').read_bytes())['cases']
    known = next(row for row in records if row['id'] == 'c2s-open-0')
    assert queries[1]['input']['record_hex'] == known['input']['record_hex']
    verdicts = ('ACCEPT', 'ACCEPT', 'ACCEPT', 'REJECT', 'REJECT')
    outputs = ({'session_id': '7_DwdcM8kMwneSBrBd-9Yg'},
               known['expected']['output'], {}, {}, {})
    return [{'verdict': verdict, 'output': output, 'effects': {
                'core_open_success': int(index >= 1),
                'core_seal_success': 0,
                'core_close_calls': int(index >= 2)}}
            for index, (verdict, output) in enumerate(zip(verdicts, outputs))]


class Session06StateTests(unittest.TestCase):
    def test_close_rejects_further_open_and_seal(self):
        result = project(ROOT, responses())
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(result['actual']['verdict'], 'REJECT')

    def test_post_close_acceptance_is_a_mismatch(self):
        rows = responses()
        rows[3]['verdict'] = 'ACCEPT'
        self.assertEqual(project(ROOT, rows)['status'], 'FAIL')

    def test_rejection_cannot_release_plaintext(self):
        rows = responses()
        rows[3]['output'] = {'plaintext_hex': '00'}
        with self.assertRaises(ValueError):
            project(ROOT, rows)


if __name__ == '__main__':
    unittest.main()
