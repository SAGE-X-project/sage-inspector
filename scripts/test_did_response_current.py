"""Synthetic verdict controls and separate native evidence for repaired responses."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import did_response_current as m
import test_did_profile_observation as fixtures


class Contracts(unittest.TestCase):
    def test_subject_and_empty_scope(self):
        selected = m.subject(); self.assertEqual(len(selected['modules']), 2)
        report = m.assess([])
        self.assertEqual(report['status_counts'], {'NOT_RUN': 580, 'UNSUPPORTED': 3})
        self.assertFalse(report['historical_results_merged'])
        with patch.object(m, 'SUBJECT_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'subject drift'): m.subject()
        with patch.object(m, 'load', return_value={}):
            with self.assertRaisesRegex(ValueError, 'closed repaired subject'): m.subject()
        bad = copy.deepcopy(selected); bad['modules'][next(iter(bad['modules']))]['Sum'] = 'invalid'
        with patch.object(m, 'load', return_value=bad):
            with self.assertRaisesRegex(ValueError, 'closed repaired module'): m.subject()

    def test_original_expectations_and_typed_mutations(self):
        self.assertEqual(m.assess(fixtures.rows())['status_counts'], {'NOT_RUN': 555, 'PARTIAL': 25, 'UNSUPPORTED': 3})
        historical = m.assess(fixtures.rows(False))
        self.assertEqual(historical['status_counts'], {'NOT_RUN': 555, 'PARTIAL': 23, 'FAIL': 2, 'UNSUPPORTED': 3})
        for member, value in [('deactivated', 0), ('deactivated', None), ('deactivated', True)]:
            rows = fixtures.rows(); row = next(x for x in rows if x['id'] == 'didp-02-json-envelope')
            body = m.load(bytes.fromhex(row['actual']['responses'][0]['body_hex']))
            body['didDocumentMetadata'][member] = value
            row['actual']['responses'][0]['body_hex'] = m.canonical(body).hex()
            self.assertEqual(m.assess(rows)['status_counts'].get('FAIL'), 1)
        rows = fixtures.rows(); rows[0]['input_sha256'] = '0' * 64
        with self.assertRaises(ValueError): m.assess(rows)

    def test_module_identity_refusals(self):
        selected = m.subject()['modules']; path = next(iter(selected))
        value = {'Path': path, **selected[path], 'Replace': {'Path': '/tmp/fixture'}}
        with patch.object(m, 'execute', return_value=type('Output', (), {'stdout': m.canonical(value)})()):
            with self.assertRaisesRegex(ValueError, 'module identity'): m.module_info('go', Path('.'), {}, selected)
        with patch.object(m, 'execute', return_value=type('Output', (), {'stdout': b'invalid'})()):
            with self.assertRaises(ValueError): m.module_info('go', Path('.'), {}, selected)

    def test_cli_and_failed_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'report.json'; counter = 0
            def invoke(args):
                nonlocal target, counter
                target = Path(tmp) / ('report-' + str(counter) + '.json'); counter += 1
                with patch.object(sys, 'argv', ['did-response', '--output', str(target)] + args): m.main()
            invoke([])
            self.assertEqual(json.loads(target.read_text())['status_counts']['NOT_RUN'], 580)
            with patch.object(m, 'run_native', return_value=m.assess(fixtures.rows())): invoke(['--native'])
            with patch.object(m, 'run_native', return_value=m.assess(fixtures.rows(False))):
                with self.assertRaises(SystemExit): invoke(['--native'])
            with patch.object(m, 'run_native', return_value=m.assess([])):
                with self.assertRaises(SystemExit): invoke(['--native'])
            with patch.object(m, 'assess', side_effect=OSError('fixture unavailable')):
                with self.assertRaises(SystemExit): invoke([])


    def test_existing_output_and_links_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = Path(tmp) / 'sentinel.json'; sentinel.write_bytes(b'original evidence')
            link = Path(tmp) / 'alias.json'; link.symlink_to(sentinel)
            fixture = m.ROOT / m.old.FIXTURE_PATH; before = fixture.read_bytes()
            for target in [sentinel, link, fixture]:
                with patch.object(sys, 'argv', ['did-response', '--output', str(target)]):
                    with self.assertRaises(SystemExit): m.main()
            self.assertEqual(sentinel.read_bytes(), b'original evidence')
            self.assertEqual(fixture.read_bytes(), before)
            self.assertTrue(link.is_symlink())


class Native(unittest.TestCase):
    def test_actual_repaired_processes(self):
        report = m.run_native(os.environ.get('SAGE_INSPECTION_GO', 'go'))
        self.assertEqual(report['status_counts'], {'NOT_RUN': 555, 'PARTIAL': 25, 'UNSUPPORTED': 3})
        self.assertEqual(report['execution']['process_count'], 25)
        self.assertEqual(len(report['execution']['raw_trace']), 25)
        self.assertEqual(report['scope']['protected_message_authority'], 'NOT_RUN')
        self.assertEqual(report['scope']['deployed_registry'], 'NOT_BOUND')
        self.assertFalse(report['historical_results_merged'])
        self.assertEqual(report['evidence_kind'], 'inspector-launched-native-DID-processes')

if __name__ == '__main__': unittest.main()
