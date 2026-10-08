"""Refuse incomplete or changed saved test evidence without sending attack traffic."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import inspect_adk_runtime as audit


class ADKRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.report = audit.strict_json(audit.REPORT.read_bytes())
        self.review = audit.catalog()

    def case(self, index=1):
        return copy.deepcopy(self.report['cases'][index]), self.review['groups'][index]

    def change(self, case, mutate):
        _, rows = audit.trace_rows(case['stdout_hex']); mutate(rows)
        raw = b''.join(audit.canonical(row) + b'\n' for row in rows)
        case['stdout_hex'] = raw.hex(); case['stdout_sha256'] = audit.sha(raw)

    def rejected(self, mutate, index=1):
        case, group = self.case(index); self.change(case, mutate)
        with self.assertRaises(ValueError): audit.check_trace(case, group)

    def test_saved_actual_runs(self):
        result = audit.check_report(self.report)
        self.assertEqual(result['top_level_tests'], 56)
        self.assertEqual(result['groups'], 3)
        self.assertGreater(result['leaf_tests'], 56)

    def test_scope_and_provenance_never_promote(self):
        for key in audit.SCOPE:
            report = copy.deepcopy(self.report); report['scope'][key] = 'PASS'
            with self.subTest(key=key), self.assertRaises(ValueError): audit.check_report(report)
        for key in ('adk_revision', 'go_revision', 'normative_source_revision', 'source_sha256', 'catalog_sha256', 'compiler', 'status'):
            report = copy.deepcopy(self.report); report[key] = 'unreviewed'
            with self.subTest(key=key), self.assertRaises(ValueError): audit.check_report(report)

    def test_all_execution_groups_required_in_order(self):
        for mode in ('missing', 'duplicate', 'reorder'):
            report = copy.deepcopy(self.report)
            if mode == 'missing': report['cases'].pop()
            elif mode == 'duplicate': report['cases'][1] = report['cases'][0]
            else: report['cases'].reverse()
            with self.subTest(mode=mode), self.assertRaises(ValueError): audit.check_report(report)

    def test_missing_test_is_not_a_successful_suite(self):
        case, group = self.case(); removed = group['tests'][next(iter(group['tests']))][0]
        self.change(case, lambda rows: rows.__setitem__(slice(None), [r for r in rows if not r.get('Test', '').startswith(removed)]))
        with self.assertRaises(ValueError): audit.check_trace(case, group)

    def test_each_native_refusal_child_is_required(self):
        for parent, children in self.review['groups'][1]['children'].items():
            for child in children:
                case, group = self.case(); removed = parent + '/' + child
                self.change(case, lambda rows: rows.__setitem__(slice(None), [r for r in rows if r.get('Test') != removed]))
                with self.subTest(child=removed), self.assertRaises(ValueError): audit.check_trace(case, group)

    def test_skipped_failed_and_build_failed_events_refuse(self):
        for action in ('skip', 'fail', 'build-fail'):
            def change(rows):
                next(r for r in rows if r['Action']=='pass' and 'Test' in r)['Action'] = action
            with self.subTest(action=action): self.rejected(change)

    def test_nonzero_process_exit_even_with_pass_logs(self):
        for value in (1, -9, True):
            case, group = self.case(); case['returncode'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): audit.check_trace(case, group)

    def test_command_cannot_disable_race_or_reuse_cached_results(self):
        for flag in ('-race', '-count=1', '-parallel=1'):
            case, group = self.case(); case['command'].remove(flag)
            with self.subTest(flag=flag), self.assertRaises(ValueError): audit.check_trace(case, group)
        self.rejected(lambda rows: next(r for r in rows if r['Action']=='output').update(Output='ok (cached)\n'))
        self.rejected(lambda rows: next(r for r in rows if r['Action']=='output').update(Output='WARNING: DATA RACE\n'))

    def test_module_identity_and_integrity_required(self):
        for key in audit.GO_MODULE:
            case, group = self.case(); case['module'][key] = 'replacement'
            with self.subTest(key=key), self.assertRaises(ValueError): audit.check_trace(case, group)
        for value in (False, 1, None):
            case, group = self.case(); case['modules_verified'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): audit.check_trace(case, group)

    def test_logs_must_match_exact_hash_and_framing(self):
        for field in ('stdout_sha256', 'stderr_sha256'):
            case, group = self.case(); case[field] = '0'*64
            with self.subTest(field=field), self.assertRaises(ValueError): audit.check_trace(case, group)
        case, group = self.case(); raw = bytes.fromhex(case['stdout_hex'])[:-1]
        case['stdout_hex'] = raw.hex(); case['stdout_sha256'] = audit.sha(raw)
        with self.assertRaises(ValueError): audit.check_trace(case, group)
        case, group = self.case(); case['stderr_hex'] = b'unexpected diagnostic'.hex(); case['stderr_sha256'] = audit.sha(b'unexpected diagnostic')
        with self.assertRaises(ValueError): audit.check_trace(case, group)

    def test_package_and_test_terminal_events_cannot_repeat(self):
        for action in ('start', 'run', 'pass'):
            def change(rows):
                index = next(i for i, r in enumerate(rows) if r['Action']==action)
                rows.insert(index+1, copy.deepcopy(rows[index]))
            with self.subTest(action=action): self.rejected(change)

    def test_test_needs_actual_run_before_terminal(self):
        self.rejected(lambda rows: rows.pop(next(i for i,r in enumerate(rows) if r['Action']=='run')))
        self.rejected(lambda rows: rows.pop(next(i for i,r in enumerate(rows) if r['Action']=='start')))

    def test_package_cannot_complete_before_running_children(self):
        def change(rows):
            end = next(i for i, r in enumerate(rows) if r['Action']=='pass' and 'Test' not in r)
            row = rows.pop(end); rows.insert(1, row)
        self.rejected(change)

    def test_child_cannot_run_after_parent_completion(self):
        def change(rows):
            index = next(i for i,r in enumerate(rows) if r['Action']=='pass' and r.get('Test')=='TestApprovedHopOperationNativeRuntime')
            row = rows.pop(index); start = next(i for i,r in enumerate(rows) if r['Action']=='run' and r.get('Test')=='TestApprovedHopOperationNativeRuntime')
            rows.insert(start+1,row)
        self.rejected(change)

    def test_truncated_test_or_package_terminal_refuses(self):
        for is_test in (True, False):
            def change(rows):
                index = next(i for i,r in enumerate(rows) if r['Action']=='pass' and ('Test' in r)==is_test)
                rows.pop(index)
            with self.subTest(is_test=is_test): self.rejected(change)

    def test_foreign_package_and_unselected_test_refuse(self):
        self.rejected(lambda rows: rows[0].update(Package='foreign/package'))
        self.rejected(lambda rows: next(r for r in rows if r['Action']=='run').update(Test='TestUnreviewed'))

    def test_closed_report_and_event_shape(self):
        report = copy.deepcopy(self.report); report['trusted'] = True
        with self.assertRaises(ValueError): audit.check_report(report)
        case, group = self.case(); case['passed'] = True
        with self.assertRaises(ValueError): audit.check_trace(case, group)
        self.rejected(lambda rows: rows[0].update(Trusted=True))

    def test_invalid_or_unbounded_test_durations_refuse(self):
        for value in (True, -1, 181, '1'):
            def change(rows): next(r for r in rows if r['Action']=='pass')['Elapsed'] = value
            with self.subTest(value=value): self.rejected(change)

    def test_literal_slashes_in_a_test_label_are_supported(self):
        # Go does not emit a separate run for each slash inside one t.Run name.
        case, group = self.case(0)
        _, rows = audit.trace_rows(case['stdout_hex'])
        self.assertTrue(any(r['Action']=='run' and r.get('Test','').count('/')>1 for r in rows))
        audit.check_trace(case, group)

    def test_out_of_order_pause_and_continue_refuse(self):
        for action in ('pause', 'cont'):
            def change(rows): next(r for r in rows if r['Action']=='run')['Action']=action
            with self.subTest(action=action): self.rejected(change)

    def test_unreviewed_source_refuses_before_compiler(self):
        with patch.object(audit, 'check_source', side_effect=ValueError('revision')), patch.object(audit, 'module_at') as module:
            with self.assertRaises(ValueError): audit.inspect(Path('/unreviewed'))
            module.assert_not_called()

    def test_source_is_rechecked_after_execution(self):
        case, _ = self.case(0)
        observed = subprocess.CompletedProcess([],0,bytes.fromhex(case['stdout_hex']),b'')
        with patch.object(audit,'source_at',side_effect=[Path('/subject'),ValueError('late source drift')]), \
             patch.object(audit,'module_at',return_value=audit.GO_MODULE), \
             patch.object(audit.subprocess,'check_output',return_value='go version go1.26.8 darwin/arm64\n'), \
             patch.object(audit.subprocess,'run',return_value=observed):
            with self.assertRaisesRegex(ValueError,'late source drift'): audit.inspect(Path('/subject'))

    def test_module_replacement_rejected_before_integrity_check(self):
        raw=json.dumps(dict(audit.GO_MODULE,Replace={'Dir':'/unreviewed'})).encode()
        result=subprocess.CompletedProcess([],0,raw,b'')
        with patch.object(audit.subprocess,'run',return_value=result) as run:
            with self.assertRaises(ValueError): audit.module_at(Path('/subject'),{})
            self.assertEqual(run.call_count,1)


if __name__ == '__main__':
    unittest.main()
