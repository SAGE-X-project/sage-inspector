"""Scenario units and safe source-query CLI tests; inspected code never executes."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import inspect_registry_mapping_review as audit

ROOTS = {}


class MappingReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = audit.review()
        cls.sources = {name: audit.preflight.read_repository(ROOTS[name], declaration)
                       for name, declaration in audit.preflight.catalog()['repositories'].items()}

    def query(self):
        return audit.report(self.sources, self.ledger)

    def command(self, output):
        args = [sys.executable, '-B', str(audit.preflight.ROOT / 'scripts/inspect_registry_mapping_review.py')]
        for name, root in ROOTS.items():
            args += ['--' + name + '-root', str(root)]
        return args + ['--output', str(output)]

    def test_every_preflight_obligation_has_one_review_and_no_closed_evidence(self):
        result = self.query()
        expected = audit.preflight.report(self.sources, audit.preflight.catalog())
        self.assertEqual([row['id'] for row in result['obligations']],
                         [row['id'] for row in expected['findings']])
        self.assertEqual(result['classification_counts'], dict(READ_MAPPING_REQUIRED=1,
                         WRITE_SEMANTICS_REQUIRED=5, PROVIDER_BINDING_REQUIRED=1))
        self.assertEqual(result['required_evidence_count'], 21)
        ids = [item['id'] for row in result['obligations'] for item in row['required_evidence']]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(item['status'] == 'EVIDENCE_REQUIRED' for row in result['obligations']
                            for item in row['required_evidence']))

    def test_projection_cannot_fabricate_complete_record(self):
        result = self.query()
        self.assertEqual([row['field'] for row in result['record_projection']],
                         ['id', 'controller', 'keys', 'services', 'state', 'version'])
        self.assertTrue(all(row['status'] == 'NOT_BOUND' for row in result['record_projection']))
        self.assertFalse(result['read_only_projection_sufficient'])
        for change in ('omit-version', 'claim-bound', 'invent-services'):
            bad = copy.deepcopy(self.ledger)
            if change == 'omit-version':
                bad['record_projection'].pop()
            elif change == 'claim-bound':
                bad['record_projection'][0]['status'] = 'BOUND'
            else:
                bad['record_projection'][3]['required_mapping'] = 'Accept capabilities without validation'
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'ledger changed'):
                audit.report(self.sources, bad)

    def test_cannot_downgrade_write_gap_to_read_mapping_or_remove_obligation(self):
        for change in ('classification', 'omit-area', 'omit-requirement', 'claim-pass'):
            bad = copy.deepcopy(self.ledger)
            if change == 'classification':
                bad['obligations'][1]['classification'] = 'READ_MAPPING_REQUIRED'
            elif change == 'omit-area':
                bad['obligations'].pop()
            elif change == 'omit-requirement':
                bad['obligations'][0]['required_evidence'].pop()
            else:
                bad['obligations'][4]['required_evidence'][0]['status'] = 'PASS'
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'ledger changed'):
                audit.report(self.sources, bad)

    def test_cannot_rebind_review_to_other_source_or_normative_revision(self):
        for change in ('catalog', 'span', 'normative-rule'):
            bad = copy.deepcopy(self.ledger)
            if change == 'catalog':
                bad['preflight_catalog_sha256'] = '0' * 64
            elif change == 'span':
                bad['reviewed_spans'][-1]['line'] += 1
            else:
                bad['obligations'][4]['normative_rules'] = ['REG-08']
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'ledger changed'):
                audit.report(self.sources, bad)
        bad = copy.deepcopy(self.sources)
        bad['contracts']['ethereum/contracts/AgentCardRegistry.sol'] += b'\n'
        with self.assertRaisesRegex(ValueError, 'source hash drift'):
            audit.report(bad, self.ledger)

    def test_new_operator_and_provider_anchors_are_exact_committed_bytes(self):
        result = self.query()
        spans = {item['id']: item for item in result['reviewed_spans']}
        self.assertEqual(len(spans), len(result['reviewed_spans']))
        for row in result['obligations']:
            for ident in row['source_spans']:
                span = spans[ident]
                lines = self.sources[span['repository']][span['path']].splitlines(keepends=True)
                self.assertEqual(audit.preflight.sha(b''.join(lines[span['line'] - 1:span['end_line']])),
                                 span['sha256'])
        self.assertIn('operator-write', spans)
        self.assertIn('normative-operator', spans)
        self.assertIn('core-source-contract', spans)
        self.assertIn('adk-instance-contract', spans)

    def test_success_never_attests_deployment_host_or_effect(self):
        result = self.query()
        self.assertEqual(result['mapping_review_status'], 'SOURCE_REVIEW_COMPLETE')
        self.assertEqual(result['binding_readiness'], 'UNRESOLVED')
        self.assertEqual(result['connection_authorization'], 'NOT_GRANTED')
        for key in ('selected_deployment', 'selected_host', 'effect_observations'):
            self.assertIsNone(result[key])
        for key in ('live_chain_verification', 'contract_compilation', 'contract_execution',
                    'loaded_instance_attestation', 'independent_hop_execution'):
            self.assertEqual(result[key], 'NOT_RUN')
        self.assertEqual(result['deployed_host_controls'], dict(count=13, status='NOT_RUN'))
        self.assertEqual(result['full_conformance'], 'NOT_ESTABLISHED')

    def test_file_hash_rejects_semantically_similar_edited_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'review.json'
            path.write_text(json.dumps(self.ledger))
            with self.assertRaisesRegex(ValueError, 'ledger changed'):
                audit.review(path)

    def test_runtime_cli_reproduces_report_and_refuses_scope_promotion(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'actual.json'
            saved = audit.preflight.ROOT / 'docs/evidence/registry-mapping-review.json'
            run = subprocess.run(self.command(output) + ['--check', str(saved)],
                                 capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(output.read_text()), self.query())
            output.unlink()
            bad = json.loads(saved.read_text())
            bad['binding_readiness'] = 'READY'
            forged = Path(tmp) / 'changed.json'
            forged.write_text(json.dumps(bad))
            run = subprocess.run(self.command(output) + ['--check', str(forged)],
                                 capture_output=True, text=True, timeout=60)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('saved mapping report drift', run.stderr)
            self.assertFalse(output.exists())

    def test_runtime_cli_missing_source_refuses_without_fresh_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'actual.json'
            command = self.command(output)
            command[command.index('--contracts-root') + 1] = tmp
            run = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(run.stdout, '')
            self.assertFalse(output.exists())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('contracts', 'spec', 'go', 'adk'):
        parser.add_argument('--' + name + '-root', type=Path, required=True)
    args, remaining = parser.parse_known_args()
    ROOTS = {name: getattr(args, name + '_root') for name in ('contracts', 'spec', 'go', 'adk')}
    unittest.main(argv=[sys.argv[0], *remaining])
