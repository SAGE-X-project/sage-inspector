"""Refuse changed, incomplete or promoted receiver-mapping evidence.

These units change only the saved report; they start no peer or host.
"""
import copy
import unittest

import inspect_receiver_mapping_interop as audit


class ReceiverMappingInteropTests(unittest.TestCase):
    def setUp(self):
        self.report = audit.strict_json(audit.REPORT.read_bytes())

    def refused(self, report):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            audit.check_report(report)

    def test_saved_observation(self):
        self.assertEqual(audit.check_report(self.report), 4)

    def test_scope_and_provenance_never_promote(self):
        for key in audit.SCOPE:
            report = copy.deepcopy(self.report)
            report['scope'][key] = 'PASS'
            with self.subTest(key=key):
                self.refused(report)
        for key in ('go_revision', 'rust_revision', 'normative_source_revision', 'status', 'kind', 'fixture_sha256'):
            report = copy.deepcopy(self.report)
            report[key] = 'unreviewed'
            with self.subTest(key=key):
                self.refused(report)
        report = copy.deepcopy(self.report)
        report['source_sha256']['go']['pkg/agent/guard010/receiver_policy.go'] = '0' * 64
        self.refused(report)

    def test_directions_complete_and_ordered(self):
        report = copy.deepcopy(self.report)
        report['cases'] = report['cases'][:3]
        self.refused(report)
        report = copy.deepcopy(self.report)
        report['cases'][2], report['cases'][3] = report['cases'][3], report['cases'][2]
        self.refused(report)

    def test_each_exchange_keeps_the_oracle(self):
        for index in range(4):
            for change in ('effects', 'status', 'ledger'):
                report = copy.deepcopy(self.report)
                server = report['cases'][index]['server']
                if change == 'effects':
                    server['effects'] = 2
                elif change == 'status':
                    server['status'] = 'unknown'
                else:
                    server['ledger_hex'] = server['ledger_hex'][:-2]
                with self.subTest(case=index, change=change):
                    self.refused(report)


if __name__ == '__main__':
    unittest.main()
