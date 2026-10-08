"""Scenario and safe CLI checks for an unpromoted host preparation report."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import inspect_adk_host_preparation as audit


class HostPreparationTests(unittest.TestCase):
    def setUp(self):
        self.report = audit.read_json(audit.REPORT)
        self.review, self.sources, self.controls = audit.catalogs()

    def refused(self, change):
        value = copy.deepcopy(self.report)
        change(value)
        with self.assertRaises(ValueError):
            audit.check_report(value)

    def test_saved_scope_and_complete_existing_controls(self):
        value = audit.check_report(self.report)
        self.assertEqual(value['source_file_count'], 444)
        self.assertEqual(len(value['provider_requirements']), 9)
        self.assertEqual([r['id'] for r in value['host_controls']],
                         [c['id'] for c in self.controls['cases']])
        self.assertEqual(len(value['host_controls']), 13)
        self.assertTrue(all(r['status'] == 'NOT_RUN' for r in value['host_controls']))

    def test_every_required_provider_must_remain_explicit(self):
        for index in range(9):
            with self.subTest(index=index):
                self.refused(lambda v: v['provider_requirements'].pop(index))

    def test_a_provider_claim_cannot_grant_readiness(self):
        for index in range(9):
            for claim in ('PASS', 'BOUND', 'READY', True):
                with self.subTest(index=index, claim=claim):
                    self.refused(lambda v: v['provider_requirements'][index].update(status=claim))

    def test_untrusted_scope_cannot_promote_execution(self):
        for field in self.report['scope']:
            with self.subTest(field=field):
                self.refused(lambda v: v['scope'].update({field: 'PASS'}))
        self.refused(lambda v: v['scope'].update(source_semantics_proven=0))
        self.refused(lambda v: v.update(status='HOST_READY'))

    def test_control_coverage_and_historical_states_cannot_change(self):
        self.refused(lambda v: v['host_controls'].pop())
        self.refused(lambda v: v['host_controls'].reverse())
        for index in range(13):
            with self.subTest(index=index):
                self.refused(lambda v: v['host_controls'][index].update(status='PASS'))

    def test_effect_and_carriage_cannot_expand(self):
        for field, value in [('tool', 'shell'), ('carriage', 'HTTP'),
                             ('binding_status', 'BOUND'), ('launch_platforms', ['darwin/arm64'])]:
            with self.subTest(field=field):
                self.refused(lambda v: v['planned_effect'].update({field: value}))
        self.refused(lambda v: v['planned_effect']['arguments'].update(a=200))
        self.refused(lambda v: v['planned_effect']['arguments'].update(a=True))
        self.refused(lambda v: v['excluded_routes'].pop())

    def test_revision_provenance_and_source_coverage_cannot_change(self):
        for field in ('adk_revision', 'normative_source_revision', 'catalog_sha256',
                      'complete_source_catalog_sha256', 'integration_target', 'source_file_count'):
            with self.subTest(field=field):
                self.refused(lambda v: v.update({field: 'foreign'}))
        self.refused(lambda v: v['source_anchors'].pop())
        self.refused(lambda v: v['source_anchors'][0].update(classification='ATTESTED'))
        self.refused(lambda v: v.update(authorization=True))

    def test_assembly_order_cannot_skip_a_gate(self):
        self.refused(lambda v: v['assembly_order'].remove('IdentityAndReadiness'))
        self.refused(lambda v: v['assembly_order'].reverse())

    def test_strict_json_rejects_duplicate_nonfinite_and_oversize(self):
        for raw in (b'{"status":"NOT_RUN","status":"PASS"}', b'{"x":NaN}',
                    b'{"x":Infinity}', b' ' * (audit.MAX_JSON + 1)):
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                audit.strict_json(raw)

    def test_reviewed_catalogs_are_immutable(self):
        for target in (audit.CATALOG, audit.RUNTIME_CATALOG, audit.CONTROLS):
            original = Path.read_bytes
            def altered(path):
                raw = original(path)
                return raw + b' ' if path == target else raw
            with self.subTest(target=target), patch.object(Path, 'read_bytes', altered), self.assertRaises(ValueError):
                audit.catalogs()

    def test_source_revision_and_dirty_checkout_refuse_before_file_reads(self):
        for answers in ([b'foreign\n'], [audit.ADK_REVISION.encode(), b'?? injected.go\n']):
            with self.subTest(answers=answers), tempfile.TemporaryDirectory() as root:
                with patch.object(audit, 'git', side_effect=answers), self.assertRaises(ValueError):
                    audit.source_at(root, self.sources, self.review)

    def test_second_source_check_refuses_concurrent_drift(self):
        with patch.object(audit, 'source_at', side_effect=[Path('/unused'), ValueError('changed')]):
            with self.assertRaises(ValueError):
                audit.observe('/unused')

    def test_tracked_and_ignored_compiler_input_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'entry.go').write_bytes(b'package inert\n')
            sources = {'source_sha256': {'entry.go': audit.sha((root / 'entry.go').read_bytes())}}
            review = {'source_anchors': []}
            for tracked, ignored in [(b'entry.go\0extra.go\0', b''),
                                     (b'entry.go\0', b'hidden.go\0')]:
                answers = [audit.ADK_REVISION.encode(), b'', tracked, ignored]
                with self.subTest(tracked=tracked, ignored=ignored):
                    with patch.object(audit, 'git', side_effect=answers), self.assertRaises(ValueError):
                        audit.source_at(root, sources, review)

    def test_source_content_and_unique_anchor_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'entry.go'; source.write_bytes(b'package inert\n')
            sources = {'source_sha256': {'entry.go': audit.sha(source.read_bytes())}}
            review = {'source_anchors': [{'path': 'entry.go', 'anchor': 'absent', 'sha256': audit.sha(source.read_bytes())}]}
            answers = [audit.ADK_REVISION.encode(), b'', b'entry.go\0', b'']
            with patch.object(audit, 'git', side_effect=answers), self.assertRaises(ValueError):
                audit.source_at(root, sources, review)
            source.write_bytes(b'changed\n')
            with patch.object(audit, 'git', side_effect=answers), self.assertRaises(ValueError):
                audit.source_at(root, sources, review)

    def cli(self, *args):
        return subprocess.run([sys.executable, '-B', str(audit.ROOT / 'scripts/inspect_adk_host_preparation.py'),
                               *map(str, args)], capture_output=True, timeout=30)

    def test_safe_saved_report_cli(self):
        result = self.cli('--check', audit.REPORT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'execution NOT_GRANTED', result.stdout)

    def test_output_without_fresh_source_is_refused_and_old_output_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'old.json'; out.write_bytes(b'historical observation')
            result = self.cli('--output', out)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(out.read_bytes(), b'historical observation')
            missing = Path(tmp) / 'new.json'
            result = self.cli('--adk-root', Path(tmp) / 'absent', '--output', missing)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(missing.exists())

    def test_altered_saved_report_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'claim.json'; value = copy.deepcopy(self.report)
            value['scope']['dispatch_authorization'] = 'GRANTED'
            out.write_bytes(audit.canonical(value))
            self.assertEqual(self.cli('--check', out).returncode, 1)

    @unittest.skipUnless(os.environ.get('ADK_PREPARATION_ROOT'), 'exact ADK source checkout not supplied')
    def test_safe_fresh_source_cli_and_exclusive_output(self):
        root = os.environ['ADK_PREPARATION_ROOT']
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'fresh.json'
            result = self.cli('--adk-root', root, '--check', audit.REPORT, '--output', out)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(audit.check_report(audit.read_json(out)), self.report)
            saved = out.read_bytes()
            self.assertEqual(self.cli('--adk-root', root, '--output', out).returncode, 1)
            self.assertEqual(out.read_bytes(), saved)


if __name__ == '__main__':
    unittest.main()
