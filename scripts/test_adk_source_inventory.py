"""Unit and safe parser-CLI tests; inert sources are never executed."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import inspect_adk_source_inventory as audit


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.parser = Path(os.environ.get('ADK_SYNTAX_PARSER', Path(cls.temp.name) / 'parser'))
        if 'ADK_SYNTAX_PARSER' not in os.environ:
            subprocess.run(['go', 'build', '-o', str(cls.parser),
                            './tools/adk-source-inventory'], cwd=audit.ROOT, check=True, timeout=60)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_catalog_and_saved_scope(self):
        suite = audit.catalog()
        saved = json.loads((audit.ROOT / 'docs/evidence/adk-source-inventory.json').read_text())
        self.assertEqual(saved['source_file_count'], 163)
        self.assertEqual(len(suite['routes']), 29)
        self.assertEqual(saved['selected_host'], None)
        self.assertEqual(saved['effect_observations'], None)
        self.assertEqual(saved['deployed_host_controls'], {'count': 13, 'status': 'NOT_RUN'})
        self.assertEqual(saved['adk_runtime'], 'NOT_RUN')
        self.assertEqual(saved['full_conformance'], 'NOT_ESTABLISHED')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'catalog.json'
            for change in ('adk_revision', 'sources', 'routes'):
                altered = copy.deepcopy(suite)
                altered[change] = {} if change == 'sources' else [] if change == 'routes' else '0' * 40
                path.write_text(json.dumps(altered))
                with self.assertRaisesRegex(ValueError, 'catalog changed'):
                    audit.catalog(path)

    def test_approved_operation_snapshot_is_separate_and_pinned(self):
        historical = audit.catalog()
        approved = audit.catalog(snapshot='approved-operation')
        self.assertEqual(historical['adk_revision'], audit.ADK_REVISION)
        self.assertEqual(approved['adk_revision'], 'fb98773df57b258c29ff9c355d062158bdf56c0e')
        self.assertEqual(len(approved['sources']), 169)
        self.assertEqual(len(approved['routes']), 49)
        self.assertEqual(approved['host_port_catalog_sha256'], historical['host_port_catalog_sha256'])
        new = [r for r in approved['routes'] if r['classification'] == 'APPROVED_OPERATION_OPT_IN']
        self.assertEqual(len(new), 20)
        self.assertEqual(approved['routes'][:29], historical['routes'])
        saved = json.loads((audit.ROOT / 'docs/evidence/adk-approved-operation.json').read_text())
        self.assertEqual(saved['adk_revision'], approved['adk_revision'])
        self.assertEqual(saved['catalog_sha256'], audit.SNAPSHOTS['approved-operation']['sha256'])
        self.assertEqual(saved['source_file_count'], 169)
        self.assertEqual(saved['route_classification_counts']['APPROVED_OPERATION_OPT_IN'], 20)
        self.assertEqual(saved['routes'], [dict(r, anchor_status='MATCHED') for r in approved['routes']])
        self.assertEqual(audit.sha((audit.ROOT / 'docs/evidence/adk-source-inventory.json').read_bytes()),
                         'ebeb724f05757eb4f132b29e8c2931efa2f62078a9a54d3ac2b6819593e6c4ad')
        with self.assertRaisesRegex(ValueError, 'unknown snapshot'):
            audit.catalog(snapshot='latest')
        with self.assertRaisesRegex(ValueError, 'catalog changed'):
            audit.catalog(audit.CATALOG, snapshot='approved-operation')

    def test_approved_anchor_and_revision_mixing_is_refused(self):
        suite = audit.catalog(snapshot='approved-operation')
        files = []
        for path, digest in sorted(suite['sources'].items()):
            declarations = [dict(name=r['declaration'], exported=True, line=r['line'],
                                 end_line=max([r['line']] + [c['line'] for c in r['calls']]),
                                 calls=copy.deepcopy(r['calls']))
                            for r in suite['routes'] if r['path'] == path]
            files.append(dict(path=path, sha256=digest, package='fixture',
                              declarations=declarations, initializer_calls=[]))
        inventory = dict(schema_version=1, kind='GO_SYNTAX_INVENTORY', files=files)
        result = audit.report(inventory, suite)
        self.assertEqual(result['adk_revision'], suite['adk_revision'])
        self.assertEqual(result['route_classification_counts']['APPROVED_OPERATION_OPT_IN'], 20)
        self.assertEqual(result['deployed_host_controls'], {'count': 13, 'status': 'NOT_RUN'})
        self.assertIsNone(result['selected_host'])
        self.assertIsNone(result['effect_observations'])
        self.assertEqual(result['adk_runtime'], 'NOT_RUN')
        self.assertEqual(result['independent_hop_execution'], 'NOT_RUN')
        self.assertEqual(result['full_conformance'], 'NOT_ESTABLISHED')
        for mutation in ('revision', 'normative', 'review', 'classification'):
            bad = copy.deepcopy(suite)
            if mutation == 'revision':
                bad['adk_revision'] = audit.ADK_REVISION
            elif mutation == 'normative':
                bad['normative_source_revision'] = '0' * 40
            elif mutation == 'review':
                bad['routes'][-1]['review'] = 'Fully certified'
            else:
                bad['routes'][-1]['classification'] = 'PASS'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                audit.report(inventory, bad)
        for ident in ('approved-freshness', 'approved-final-effect', 'approved-retirement'):
            r = next(r for r in suite['routes'] if r['id'] == ident)
            for mutation in ('missing', 'duplicate'):
                bad = copy.deepcopy(inventory)
                d = next(d for f in bad['files'] if f['path'] == r['path']
                         for d in f['declarations'] if d['name'] == r['declaration'])
                if mutation == 'missing':
                    d['calls'].pop()
                else:
                    d['calls'].append(copy.deepcopy(d['calls'][-1]))
                with self.subTest(anchor=ident, mutation=mutation), self.assertRaisesRegex(ValueError, 'call missing'):
                    audit.report(bad, suite)
        with self.assertRaises(ValueError):
            audit.report(inventory, audit.catalog())

    def test_calculator_snapshot_preserves_history_and_scope(self):
        approved = audit.catalog(snapshot='approved-operation')
        suite = audit.catalog(snapshot='compiled-calculator')
        self.assertEqual(suite['adk_revision'], '1da9d02226bd690f92ccc4198638afc84579a9e8')
        self.assertEqual(suite['routes'][:49], approved['routes'])
        self.assertEqual(len(suite['routes']), 59)
        self.assertEqual(len(suite['sources']), 170)
        self.assertEqual(set(suite['sources']) - set(approved['sources']),
                         {'core/guardcalculator/calculator.go'})
        self.assertEqual({p: suite['sources'][p] for p in approved['sources']}, approved['sources'])
        self.assertEqual(suite['module_files'], approved['module_files'])
        self.assertEqual(suite['host_port_catalog_sha256'], approved['host_port_catalog_sha256'])
        self.assertEqual(suite['normative_source_revision'], audit.NORMATIVE_REVISION)
        self.assertEqual(audit.sha((audit.ROOT / 'docs/evidence/adk-approved-operation.json').read_bytes()),
                         'b9a2d129cc96ad2be68556e21295629dedc1ebc9d0558c2767f37a247bcad773')
        saved = json.loads((audit.ROOT / 'docs/evidence/adk-compiled-calculator.json').read_text())
        self.assertEqual(saved['routes'], [dict(r, anchor_status='MATCHED') for r in suite['routes']])
        self.assertEqual(saved['catalog_sha256'], audit.SNAPSHOTS['compiled-calculator']['sha256'])
        self.assertEqual(saved['source_file_count'], 170)
        self.assertEqual(saved['route_classification_counts']['COMPILED_CALCULATOR_OPT_IN'], 9)
        self.assertEqual(saved['route_classification_counts']['LEGACY_UNMEDIATED'],
                         json.loads((audit.ROOT / 'docs/evidence/adk-approved-operation.json').read_text())
                         ['route_classification_counts']['LEGACY_UNMEDIATED'] + 1)
        for field, expected in dict(selected_host=None, effect_observations=None,
                                    host_selection='SELECTION_PENDING', adk_runtime='NOT_RUN',
                                    independent_hop_execution='NOT_RUN',
                                    full_conformance='NOT_ESTABLISHED',
                                    deployed_host_controls={'count': 13, 'status': 'NOT_RUN'}).items():
            self.assertEqual(saved[field], expected)
        for name in ('routes', 'approved-operation'):
            with self.subTest(snapshot=name), self.assertRaisesRegex(ValueError, 'catalog changed'):
                audit.catalog(audit.SNAPSHOTS[name]['path'], snapshot='compiled-calculator')

    def test_calculator_boundaries_refuse_missing_duplicate_and_forged_evidence(self):
        suite = audit.catalog(snapshot='compiled-calculator')
        inventory = dict(schema_version=1, kind='GO_SYNTAX_INVENTORY', files=[
            dict(path=path, sha256=digest, package='fixture', initializer_calls=[], declarations=[
                dict(name=r['declaration'], exported=True, line=r['line'],
                     end_line=max([r['line']] + [c['line'] for c in r['calls']]),
                     calls=copy.deepcopy(r['calls']))
                for r in suite['routes'] if r['path'] == path])
            for path, digest in sorted(suite['sources'].items())])
        result = audit.report(inventory, suite)
        self.assertEqual(result['full_conformance'], 'NOT_ESTABLISHED')
        for ident in ('calculator-load', 'calculator-measurement', 'calculator-instance-check',
                      'calculator-final-effect', 'calculator-retirement', 'calculator-builtin'):
            r = next(r for r in suite['routes'] if r['id'] == ident)
            for mutation in ('missing-call', 'duplicate-call', 'missing-declaration', 'duplicate-declaration'):
                bad = copy.deepcopy(inventory)
                declarations = next(f['declarations'] for f in bad['files'] if f['path'] == r['path'])
                d = next(d for d in declarations if d['name'] == r['declaration'])
                if mutation == 'missing-call':
                    d['calls'].pop()
                elif mutation == 'duplicate-call':
                    d['calls'].append(copy.deepcopy(d['calls'][-1]))
                elif mutation == 'missing-declaration':
                    declarations.remove(d)
                else:
                    declarations.append(copy.deepcopy(d))
                with self.subTest(anchor=ident, mutation=mutation), self.assertRaises(ValueError):
                    audit.report(bad, suite)
        for mutation in ('revision', 'normative', 'source', 'classification', 'review'):
            bad = copy.deepcopy(suite)
            if mutation == 'revision':
                bad['adk_revision'] = audit.SNAPSHOTS['approved-operation']['revision']
            elif mutation == 'normative':
                bad['normative_source_revision'] = '0' * 40
            elif mutation == 'source':
                bad['sources']['core/guardcalculator/calculator.go'] = '0' * 64
            else:
                bad['routes'][-1][mutation] = 'PASS'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                audit.report(inventory, bad)
        for name in ('routes', 'approved-operation'):
            with self.subTest(snapshot=name), self.assertRaises(ValueError):
                audit.report(inventory, audit.catalog(snapshot=name))

    def test_sealed_image_snapshot_preserves_history_and_distinguishes_fixture(self):
        prior = audit.catalog(snapshot='compiled-calculator')
        suite = audit.catalog(snapshot='sealed-image')
        self.assertEqual(suite['adk_revision'], '1e70c58305edefdd302dea9b35c4a232f4c3e592')
        self.assertEqual(len(suite['sources']), 175)
        self.assertEqual(len(suite['routes']), 74)
        self.assertEqual(suite['routes'][:59], prior['routes'])
        self.assertEqual({p: suite['sources'][p] for p in prior['sources']}, prior['sources'])
        self.assertEqual(set(suite['sources']) - set(prior['sources']), {
            'core/guardimage/image.go', 'core/guardimage/image_linux.go',
            'core/guardimage/image_unsupported.go', 'core/guardimage/maps.go',
            'core/guardimage/testdata/host/main.go'})
        self.assertEqual(suite['module_files'], prior['module_files'])
        self.assertEqual(suite['host_port_catalog_sha256'], prior['host_port_catalog_sha256'])
        self.assertEqual(suite['normative_source_revision'], audit.NORMATIVE_REVISION)
        historical_hashes = {
            'adk-source-inventory': 'ebeb724f05757eb4f132b29e8c2931efa2f62078a9a54d3ac2b6819593e6c4ad',
            'adk-approved-operation': 'b9a2d129cc96ad2be68556e21295629dedc1ebc9d0558c2767f37a247bcad773',
            'adk-compiled-calculator': '4c26599efb3835a5a883cec93144e4da0ea9089bdf61a42797818e18fdcad784',
        }
        for name, digest in historical_hashes.items():
            self.assertEqual(audit.sha((audit.ROOT / ('docs/evidence/' + name + '.json')).read_bytes()), digest)
        saved = json.loads((audit.ROOT / 'docs/evidence/adk-sealed-image.json').read_text())
        self.assertEqual(saved['routes'], [dict(r, anchor_status='MATCHED') for r in suite['routes']])
        self.assertEqual(saved['catalog_sha256'], audit.SNAPSHOTS['sealed-image']['sha256'])
        self.assertEqual(saved['source_file_count'], 175)
        self.assertEqual(saved['route_classification_counts']['SEALED_IMAGE_OPT_IN'], 14)
        self.assertEqual(saved['route_classification_counts']['RUNTIME_TEST_FIXTURE'], 1)
        fixture = next(r for r in suite['routes'] if r['id'] == 'image-runtime-fixture')
        self.assertEqual(fixture['path'], 'core/guardimage/testdata/host/main.go')
        self.assertEqual(fixture['classification'], 'RUNTIME_TEST_FIXTURE')
        self.assertIn('no native Guard/admission', fixture['review'])
        for field, expected in dict(selected_host=None, effect_observations=None,
                                    host_selection='SELECTION_PENDING', adk_runtime='NOT_RUN',
                                    independent_hop_execution='NOT_RUN',
                                    full_conformance='NOT_ESTABLISHED',
                                    deployed_host_controls={'count': 13, 'status': 'NOT_RUN'}).items():
            self.assertEqual(saved[field], expected)
        for boundary in ('private instruction-page', 'worker/exec generation',
                         'child-to-supervisor', 'guardcalculator.Measurement',
                         'testdata host main', 'not a sandbox'):
            self.assertTrue(any(boundary in text for text in saved['limitations']), boundary)
        for name in ('routes', 'approved-operation', 'compiled-calculator'):
            with self.subTest(snapshot=name), self.assertRaises(ValueError):
                audit.catalog(audit.SNAPSHOTS[name]['path'], snapshot='sealed-image')
            with self.subTest(snapshot=name), self.assertRaises(ValueError):
                audit.catalog(audit.SNAPSHOTS['sealed-image']['path'], snapshot=name)

    def test_sealed_boundaries_refuse_missing_duplicate_and_forged_evidence(self):
        suite = audit.catalog(snapshot='sealed-image')
        # Synthetic anchors exercise report refusals, not execution semantics.
        inventory = dict(schema_version=1, kind='GO_SYNTAX_INVENTORY', files=[
            dict(path=path, sha256=digest, package='fixture', initializer_calls=[], declarations=[
                dict(name=r['declaration'], exported=True, line=r['line'],
                     end_line=max([r['line']] + [c['line'] for c in r['calls']]),
                     calls=copy.deepcopy(r['calls']))
                for r in suite['routes'] if r['path'] == path])
            for path, digest in sorted(suite['sources'].items())])
        result = audit.report(inventory, suite)
        self.assertEqual(result['adk_runtime'], 'NOT_RUN')
        self.assertEqual(result['full_conformance'], 'NOT_ESTABLISHED')
        # Every selected new call, including sealed-object rehash before exec,
        # live pidfd/object/maps appraisal and cleanup, must occur exactly once.
        for row in suite['routes'][59:]:
            for mutation in ('missing-declaration', 'duplicate-declaration'):
                bad = copy.deepcopy(inventory)
                ds = next(f['declarations'] for f in bad['files'] if f['path'] == row['path'])
                d = next(d for d in ds if d['name'] == row['declaration'])
                if mutation == 'missing-declaration':
                    ds.remove(d)
                else:
                    ds.append(copy.deepcopy(d))
                with self.subTest(row=row['id'], mutation=mutation), self.assertRaises(ValueError):
                    audit.report(bad, suite)
            for anchor in row['calls']:
                for mutation in ('missing-call', 'duplicate-call'):
                    bad = copy.deepcopy(inventory)
                    d = next(d for f in bad['files'] if f['path'] == row['path']
                             for d in f['declarations'] if d['name'] == row['declaration'])
                    if mutation == 'missing-call':
                        d['calls'].remove(anchor)
                    else:
                        d['calls'].append(copy.deepcopy(anchor))
                    with self.subTest(row=row['id'], anchor=anchor, mutation=mutation), self.assertRaises(ValueError):
                        audit.report(bad, suite)
        for mutation in ('revision', 'normative', 'source', 'module', 'classification', 'review', 'fixture'):
            bad = copy.deepcopy(suite)
            if mutation == 'revision':
                bad['adk_revision'] = audit.SNAPSHOTS['compiled-calculator']['revision']
            elif mutation == 'normative':
                bad['normative_source_revision'] = '0' * 40
            elif mutation == 'source':
                bad['sources']['core/guardimage/image_linux.go'] = '0' * 64
            elif mutation == 'module':
                bad['module_files']['go.mod'] = '0' * 64
            elif mutation == 'fixture':
                bad['routes'][-1]['classification'] = 'SEALED_IMAGE_OPT_IN'
            else:
                bad['routes'][-2][mutation] = 'PASS'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                audit.report(inventory, bad)
        promoted = copy.deepcopy(inventory)
        promoted['full_conformance'] = 'PASS'
        with self.assertRaises(ValueError):
            audit.report(promoted, suite)
        for name in ('routes', 'approved-operation', 'compiled-calculator'):
            with self.subTest(snapshot=name), self.assertRaises(ValueError):
                audit.report(inventory, audit.catalog(snapshot=name))

    def test_runtime_query_refuses_unreviewed_revision_without_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'source'
            root.mkdir()
            (root / 'source.go').write_text('package inert\nfunc Run(){panic("must never execute")}\n')
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', '-c', 'user.name=Inspector fixture', '-c', 'user.email=fixture@invalid.local',
                            '-c', 'commit.gpgsign=false', 'commit', '-qm', 'test: retain inert source'],
                           cwd=root, check=True)
            for snapshot in audit.SNAPSHOTS:
                output = Path(tmp) / (snapshot + '.json')
                result = subprocess.run(['python3', '-B', str(audit.ROOT / 'scripts/inspect_adk_source_inventory.py'),
                                         '--snapshot', snapshot, '--adk-root', str(root),
                                         '--parser', str(self.parser), '--output', str(output)],
                                        text=True, capture_output=True, timeout=10)
                with self.subTest(snapshot=snapshot):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, '')
                    self.assertIn('ADK revision mismatch', result.stderr)
                    self.assertFalse(output.exists())

    def test_anchor_and_ast_refusal(self):
        suite = audit.catalog()
        # Bounded synthetic AST mirrors only reviewed anchors. This unit fixture
        # tests report refusal, not source parsing or semantic Guard verification.
        files = []
        for path, digest in sorted(suite['sources'].items()):
            declarations = []
            for r in suite['routes']:
                if r['path'] == path:
                    declarations.append(dict(name=r['declaration'], exported=True,
                                             line=r['line'], end_line=max([r['line']] + [c['line'] for c in r['calls']]),
                                             calls=copy.deepcopy(r['calls'])))
            files.append(dict(path=path, sha256=digest, package='fixture',
                              declarations=declarations, initializer_calls=[]))
        inventory = dict(schema_version=1, kind='GO_SYNTAX_INVENTORY', files=files)
        result = audit.report(inventory, suite)
        self.assertEqual(result['full_conformance'], 'NOT_ESTABLISHED')
        for mutation in ('hash', 'missing', 'extra', 'call', 'declaration', 'promotion', 'line'):
            bad = copy.deepcopy(inventory)
            f = next(f for f in bad['files'] if f['path'] == 'core/toolhost/executor.go')
            d = f['declarations'][0]
            if mutation == 'hash':
                f['sha256'] = '0' * 64
            elif mutation == 'missing':
                bad['files'].pop()
            elif mutation == 'extra':
                bad['files'].append(copy.deepcopy(f))
            elif mutation == 'call':
                d['calls'].pop()
            elif mutation == 'declaration':
                d['name'] = 'different'
            elif mutation == 'promotion':
                bad['full_conformance'] = 'PASS'
            else:
                d['line'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                audit.report(bad, suite)

    def test_runtime_cli_parses_but_never_executes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Imports need not exist: dependency loading is deliberately absent.
            source = 'package inert\nimport "missing.invalid/dependency"\nfunc init(){ dependency.Create("PRIVATE_LITERAL") }\nfunc Run(){ panic("must never execute") }\n'
            (root / 'inert.go').write_text(source)
            command = [str(self.parser), '--root', str(root)]
            result = subprocess.run(command, input='["inert.go"]', text=True,
                                    capture_output=True, timeout=10, check=True)
            data = json.loads(result.stdout)
            self.assertEqual(data['files'][0]['declarations'][0]['calls'][0]['callee'], 'dependency.Create')
            self.assertNotIn('PRIVATE_LITERAL', result.stdout)
            self.assertEqual(result.stdout, subprocess.check_output(command, input=b'["inert.go"]').decode())
            (root / 'broken.go').write_text('package {')
            denied = subprocess.run(command, input='["broken.go","inert.go"]', text=True,
                                    capture_output=True, timeout=10)
            self.assertNotEqual(denied.returncode, 0)
            self.assertEqual(denied.stdout, '')

    def test_checkout_drift_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'source.go').write_text('package inert\n')
            (root / '.gitignore').write_text('ignored.go\n')
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', '-c', 'user.name=Inspector fixture', '-c', 'user.email=fixture@invalid.local',
                            '-c', 'commit.gpgsign=false', 'commit', '-qm', 'test: retain inert source'], cwd=root, check=True)
            suite = dict(adk_revision=audit.git(root, 'rev-parse', 'HEAD').decode().strip(),
                         sources={'source.go': audit.sha((root / 'source.go').read_bytes())}, module_files={})
            self.assertEqual(audit.check_source(root, suite)[1], ['source.go'])
            wrong = dict(suite, adk_revision='0' * 40)
            with self.assertRaisesRegex(ValueError, 'revision mismatch'):
                audit.check_source(root, wrong)
            for name in ('source.go', 'added.go', 'ignored.go'):
                old = (root / name).read_bytes() if (root / name).exists() else None
                (root / name).write_text('package changed\n')
                with self.assertRaises(ValueError):
                    audit.check_source(root, suite)
                if old is None:
                    (root / name).unlink()
                else:
                    (root / name).write_bytes(old)
            drift = dict(suite, sources={'source.go': '0' * 64})
            with self.assertRaisesRegex(ValueError, 'hash drift'):
                audit.check_source(root, drift)


if __name__ == '__main__':
    unittest.main()
