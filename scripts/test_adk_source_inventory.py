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
