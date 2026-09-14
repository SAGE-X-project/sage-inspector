"""Aggregation regressions use frozen actual-core reports, never fake core results."""
import copy
import json
import unittest
import subprocess
import sys
import tempfile
from pathlib import Path
from inspect_http import ROOT, SUITES, summarize


class HTTPInspectionTests(unittest.TestCase):
    def setUp(self):
        names = {'http-signatures': 'http-go', 'http-boundaries': 'http-boundaries-go',
                 'http-envelope-primitives': 'http-envelope-primitives-go'}
        self.pairs = [( (ROOT/'vectors/0.10.0'/f'{name}.json').read_bytes(),
                       json.loads((ROOT/'docs/evidence'/f'{names[name]}.json').read_text())) for name in SUITES]
        # Historical binaries differ; explicitly normalize only the test subject ID
        # for aggregation unit tests. Actual command runs require identical hashes.
        subject = self.pairs[0][1]['subject']
        for _, report in self.pairs:
            report['subject'] = copy.deepcopy(subject)

    def test_counts_and_conditional_cases(self):
        report = summarize(self.pairs)
        self.assertEqual(report['counts'], {'PASS': 51, 'FAIL': 8, 'UNSUPPORTED': 75, 'NOT_RUN': 0})
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(len(report['conditional_cases']), 6)
        self.assertIn('TRANSPORT-03', report['rules'])

    def test_missing_suite(self):
        with self.assertRaises(ValueError):
            summarize(self.pairs[:-1])

    def test_corrupt_reports(self):
        for change in ('hash', 'subject', 'count', 'missing', 'duplicate', 'promoted'):
            with self.subTest(change=change):
                pairs = copy.deepcopy(self.pairs)
                report = pairs[1][1]
                if change == 'hash':
                    report['suite_sha256'] = '0'*64
                elif change == 'subject':
                    report['subject']['revision'] = 'different'
                elif change == 'count':
                    report['counts']['PASS'] += 1
                elif change == 'missing':
                    report['results'].pop()
                elif change == 'duplicate':
                    report['results'][1] = report['results'][0]
                else:
                    report['results'][0]['status'] = 'PASS'
                with self.assertRaises(ValueError):
                    summarize(pairs)

    def test_existing_evidence_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory)/'marker'
            marker.write_text('keep')
            result = subprocess.run([sys.executable, str(ROOT/'scripts/inspect_http.py'),
                                     '--runner', sys.executable, '--adapter', sys.executable,
                                     '--subject', 'test', '--revision', 'test', '--output-dir', directory],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(marker.read_text(), 'keep')

    def test_all_pass_is_still_conditional(self):
        # Synthetic runner results exercise only the conclusion gate, not a core.
        pairs = copy.deepcopy(self.pairs)
        for _, report in pairs:
            for result in report['results']:
                result['status'] = 'PASS'
                result['actual'] = {'schema_version': 1, 'case_id': result['case_id'], 'verdict': result['expected']['verdict'], 'output': result['expected']['output']}
            report['counts'] = {'PASS': len(report['results']), 'FAIL': 0, 'UNSUPPORTED': 0, 'NOT_RUN': 0}
            report['status'] = 'PASS'
        self.assertEqual(summarize(pairs)['status'], 'INCOMPLETE')


if __name__ == '__main__':
    unittest.main()
