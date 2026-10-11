"""Refuse incomplete, changed or promoted demo comparison evidence.

These units change only the saved report. They start no demo, host, signer or
relay process.
"""
import copy
import unittest

import inspect_demo_comparison as audit


def run_index(mode, scenario):
    return [(m, n) for m, n, _ in audit.runs()].index((mode, scenario))


class DemoComparisonTests(unittest.TestCase):
    def setUp(self):
        self.report = audit.strict_json(audit.REPORT.read_bytes())

    def refused(self, report):
        with self.assertRaises(ValueError):
            audit.check_report(report)

    def changed(self, mode, scenario, change):
        report = copy.deepcopy(self.report)
        change(report['runs'][run_index(mode, scenario)])
        return report

    def test_saved_observation(self):
        summary = audit.check_report(self.report)
        self.assertEqual(summary['status'], 'BOUNDED_DEMO_COMPARISON_OBSERVED')
        self.assertEqual(summary['baseline_harmed'], 4)
        self.assertEqual(summary['sage_harmed'], 0)
        self.assertGreaterEqual(summary['setup_wait_ms'], audit.QUARANTINE_MS)

    def test_scope_and_provenance_never_promote(self):
        for key in audit.SCOPE:
            report = copy.deepcopy(self.report)
            report['scope'][key] = 'PASS'
            with self.subTest(key=key):
                self.refused(report)
        for key in ('demo_revision', 'adk_module', 'core_module', 'normative_source_revision',
                    'compiler', 'status', 'kind', 'protocol_version'):
            report = copy.deepcopy(self.report)
            report[key] = 'unreviewed'
            with self.subTest(key=key):
                self.refused(report)
        report = copy.deepcopy(self.report)
        report['extra'] = True
        self.refused(report)

    def test_report_revisions_must_be_clean_and_pinned(self):
        for key, value in (('demo', audit.DEMO_REVISION + '+modified'), ('core', 'v1.5.3'), ('spec', 'other')):
            def change(r, key=key, value=value):
                r['revisions'][key] = value
            with self.subTest(key=key):
                self.refused(self.changed('sage', 'normal', change))

    def test_every_run_is_required_in_order(self):
        report = copy.deepcopy(self.report)
        report['runs'].pop()
        self.refused(report)
        report = copy.deepcopy(self.report)
        report['runs'][0], report['runs'][1] = report['runs'][1], report['runs'][0]
        self.refused(report)

    def test_weaker_protected_outcomes(self):
        approved = audit.entry(1, audit.APPROVED)
        cases = {
            'tamper-ran': ('tamper-args', lambda r: r['ledger'].append(approved)),
            'tamper-unchanged': ('tamper-args', lambda r: r['fault_changed'].clear()),
            'tamper-too-early': ('tamper-args', lambda r: r['relay_frames'][0].update(responses=1)),
            'replay-answered': ('replay', lambda r: r['replay'].update(answered_frames=1)),
            'replay-ran-twice': ('replay', lambda r: r['ledger'].append(audit.entry(2, audit.APPROVED))),
            'unapproved-sent': ('unapproved', lambda r: r['relay_frames'].append({'requests': 1, 'responses': 0})),
            'forge-accepted': ('forge-result', lambda r: r['calls'][0].update(result=audit.FORGED)),
            'forge-never-ran': ('forge-result', lambda r: r['ledger'].clear()),
            'normal-refused': ('normal', lambda r: r['calls'][0].update(error='denied')),
            'harm-claimed': ('normal', lambda r: r['harms'].append('h')),
            'mismatch': ('replay', lambda r: r['mismatches'].append('m')),
            'not-as-expected': ('replay', lambda r: r.update(as_expected=False)),
            'notes-dropped': ('normal', lambda r: r['notes'].clear()),
        }
        for name, (scenario, change) in cases.items():
            with self.subTest(case=name):
                self.refused(self.changed('sage', scenario, change))

    def test_baseline_must_show_the_harm(self):
        cases = {
            'tamper-refused': ('tamper-args', lambda r: r['ledger'].clear()),
            'replay-once': ('replay', lambda r: r['ledger'].pop()),
            'forge-real-result': ('forge-result', lambda r: r['calls'][0].update(result={'balance': 990, 'transfer_id': 't-000001'})),
            'harms-dropped': ('unapproved', lambda r: r['harms'].clear()),
        }
        for name, (scenario, change) in cases.items():
            with self.subTest(case=name):
                self.refused(self.changed('baseline', scenario, change))

    def test_setup_and_comparison(self):
        report = copy.deepcopy(self.report)
        report['setup']['setup']['quarantine_wait_ms'] = 1000
        self.refused(report)
        report = copy.deepcopy(self.report)
        report['setup']['calls'][0] = {'error': 'denied', 'elapsed_ms': 1}
        self.refused(report)
        for text in ('DIFFERS FROM EXPECTATION', 'not run', 'sage setup failed'):
            report = copy.deepcopy(self.report)
            report['compare'] += text
            with self.subTest(text=text):
                self.refused(report)


if __name__ == '__main__':
    unittest.main()
