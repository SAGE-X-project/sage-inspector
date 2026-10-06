"""Unit and safe CLI tests of committed source review, never contract execution."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import inspect_registry_contract_preflight as audit


def parameter(name, kind, components=None):
    value = dict(name=name, type=kind)
    if components is not None:
        value['components'] = components
    return value


class PreflightTests(unittest.TestCase):
    def test_abi_projection_keeps_output_types_and_order(self):
        item = dict(type='function', name='getAgent', stateMutability='view',
                    inputs=[parameter('agentId', 'bytes32')],
                    outputs=[parameter('', 'tuple', [parameter('did', 'string'), parameter('active', 'bool')])])
        result = audit.function([item], 'getAgent')
        self.assertEqual(result, item)
        old = copy.deepcopy(item)
        old['outputs'][0]['components'][1] = parameter('publicKey', 'bytes')
        self.assertNotEqual(audit.function([old], 'getAgent'), result)
        for bad in ([item, item], [], [dict(item, stateMutability='unknown')]):
            with self.assertRaises(ValueError):
                audit.function(bad, 'getAgent')

    def test_tuple_bounds_and_closed_projected_fields(self):
        item = dict(type='function', name='read', stateMutability='view', inputs=[],
                    outputs=[parameter('', 'tuple', [parameter('version', 'uint256')])])
        for mutation in ('missing-components', 'duplicate-name', 'wrong-type', 'deep'):
            bad = copy.deepcopy(item)
            p = bad['outputs'][0]
            if mutation == 'missing-components':
                p.pop('components')
            elif mutation == 'duplicate-name':
                p['components'].append(copy.deepcopy(p['components'][0]))
            elif mutation == 'wrong-type':
                p['components'][0]['type'] = False
            else:
                for _ in range(10):
                    p = p['components'][0]
                    p['type'] = 'tuple'
                    p['components'] = [parameter('nested', 'string')]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                audit.function([bad], 'read')

    def test_abi_scalar_widths_and_array_bounds(self):
        for kind in ('bytes33', 'bytes0', 'bytes01', 'uint7', 'int264', 'uint0', 'uint08',
                     'string[0]', 'bytes32[01]', 'uint256' + '[]' * 9):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                audit.parameter(parameter('value', kind))
        for kind in ('bytes', 'bytes32', 'uint256', 'int8', 'uint', 'string[]', 'bytes32[10]'):
            self.assertEqual(audit.parameter(parameter('value', kind)), parameter('value', kind))

    def test_catalog_is_fixed_and_not_a_deployment(self):
        catalog = audit.catalog()
        self.assertEqual(catalog['repositories']['contracts']['revision'],
                         'd9f313b1057d299423d800c846751ed40282a116')
        self.assertEqual(catalog['repositories']['spec']['revision'],
                         '1820ab5eafb843e1c13f4c46c34aeeb28d934ac9')
        self.assertEqual(sum(len(r['files']) for r in catalog['repositories'].values()), 16)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'changed.json'
            for field in ('repositories', 'reviewed_spans'):
                bad = copy.deepcopy(catalog)
                bad[field] = {}
                path.write_text(json.dumps(bad))
                with self.assertRaisesRegex(ValueError, 'catalog changed'):
                    audit.catalog(path)

    def test_saved_report_does_not_grant_authority(self):
        report = json.loads((audit.ROOT / 'docs/evidence/registry-contract-preflight.json').read_text())
        self.assertEqual(report['binding_readiness'], 'REVIEW_REQUIRED')
        self.assertEqual(report['live_chain_verification'], 'NOT_RUN')
        self.assertEqual(report['contract_compilation'], 'NOT_RUN')
        self.assertEqual(report['contract_execution'], 'NOT_RUN')
        self.assertEqual(report['loaded_instance_attestation'], 'NOT_RUN')
        self.assertEqual(report['full_conformance'], 'NOT_ESTABLISHED')
        self.assertIsNone(report['selected_deployment'])
        self.assertIsNone(report['effect_observations'])
        self.assertEqual(report['deployed_host_controls'], {'count': 13, 'status': 'NOT_RUN'})
        self.assertEqual(len(report['findings']), 7)
        self.assertTrue(all(r['status'] == 'MAPPING_REVIEW_REQUIRED' for r in report['findings']))
        self.assertEqual(report['abi_projections']['AgentCardRegistry']['getAgent']['outputs'][0]['components'][4]['name'], 'keyHashes')
        self.assertEqual(report['abi_projections']['ISageRegistry']['getAgent']['outputs'][0]['components'][4]['name'], 'publicKey')

    def test_report_refuses_modified_review_and_missing_or_changed_sources(self):
        reviewed = audit.catalog()
        for mutation in ('revision', 'span'):
            bad = copy.deepcopy(reviewed)
            if mutation == 'revision':
                bad['repositories']['contracts']['revision'] = '0' * 40
            else:
                bad['reviewed_spans'][0]['line'] += 1
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'catalog changed'):
                audit.report({}, bad)
        with self.assertRaisesRegex(ValueError, 'repository set drift'):
            audit.report({}, reviewed)
        bad = {name: {} for name in reviewed['repositories']}
        with self.assertRaisesRegex(ValueError, 'file set drift'):
            audit.report(bad, reviewed)
        bad = {name: {path: b'inert changed bytes' for path in declaration['files']}
               for name, declaration in reviewed['repositories'].items()}
        with self.assertRaisesRegex(ValueError, 'source hash drift'):
            audit.report(bad, reviewed)

    def test_committed_read_never_uses_dirty_worktree_or_executes_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'source.txt').write_text('reviewed bytes\n')
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', '-c', 'user.name=Inspector fixture', '-c', 'user.email=fixture@invalid.local',
                            '-c', 'commit.gpgsign=false', 'commit', '-qm', 'test: retain inert bytes'], cwd=root, check=True)
            revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
            (root / 'source.txt').write_text('uncommitted change\n')
            expected = dict(revision=revision, files={'source.txt': audit.sha(b'reviewed bytes\n')})
            self.assertEqual(audit.read_repository(root, expected), {'source.txt': b'reviewed bytes\n'})
            for bad in (dict(expected, revision='0' * 40),
                        dict(expected, files={'source.txt': '0' * 64}),
                        dict(expected, files={'missing.txt': '0' * 64})):
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    audit.read_repository(root, bad)

    def test_runtime_cli_refuses_missing_repository_without_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'report.json'
            command = [sys.executable, '-B', str(audit.ROOT / 'scripts/inspect_registry_contract_preflight.py')]
            for name in ('contracts', 'spec', 'go', 'adk'):
                command += ['--' + name + '-root', tmp]
            result = subprocess.run(command + ['--output', str(output)], text=True,
                                    capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
