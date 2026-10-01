"""Unit checks for strict DID evidence identity and fail-closed report auditing."""

import copy
import unittest

from check_strict_did010_reports import assess, suite


class StrictDIDReportsTests(unittest.TestCase):
    def test_suite_keeps_canonical_and_legacy_controls_separate(self):
        cases = {case['id']: case for case in suite()['cases']}
        self.assertEqual(len(cases), 20)
        self.assertEqual(cases['canonical-web']['expected']['verdict'], 'ACCEPT')
        self.assertEqual(cases['canonical-key-url']['expected']['verdict'], 'ACCEPT')
        self.assertEqual(cases['legacy-alias']['expected']['verdict'], 'REJECT')
        self.assertEqual(cases['reserved-kind']['expected']['verdict'], 'REJECT')

    def test_report_auditor_rejects_status_or_result_promotion(self):
        cases = suite()['cases']
        report = {
            'schema_version': 1, 'suite_id': 'sage-strict-did-0.10.0',
            'protocol_version': '0.10.0', 'profile': 'primitive-foundation',
            'suite_sha256': '42bce21df8d10ac3ebe9ecb790bd398997813a471cec7d9e66eee3c80a65daef',
            'sources': suite()['sources'],
            'scope': ('Only listed primitive cases; no full SAGE, '
                      'state-machine, registry or Execution Guard certification.'),
            'subject': {'kind': 'external', 'revision': 'pinned',
                        'executable_sha256': 'a' * 64},
            'status': 'PASS',
            'counts': {'PASS': len(cases), 'FAIL': 0, 'UNSUPPORTED': 0, 'NOT_RUN': 0},
            'results': [{'case_id': case['id'], 'operation': case['operation'],
                         'rule_ids': case['rule_ids'], 'source_ids': case['source_ids'],
                         'expected': case['expected'], 'status': 'PASS',
                         'actual': {'schema_version': 1, 'case_id': case['id'],
                                    'verdict': case['expected']['verdict'],
                                    'output': case['expected']['output']}}
                        for case in cases],
        }
        assess('synthetic', report, cases, 'pinned')
        changed = copy.deepcopy(report)
        changed['results'][0]['actual']['verdict'] = 'REJECT'
        with self.assertRaisesRegex(ValueError, 'canonical-web'):
            assess('synthetic', changed, cases, 'pinned')
        changed = copy.deepcopy(report)
        changed['results'][15]['status'] = 'UNSUPPORTED'
        with self.assertRaisesRegex(ValueError, 'canonical-key-url'):
            assess('synthetic', changed, cases, 'pinned')


if __name__ == '__main__':
    unittest.main()
