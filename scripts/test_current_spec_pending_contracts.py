"""Partial host contracts do not manufacture implementation observations."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from check_current_spec_pending_contracts import check
from current_spec_pending_bridge import observe
from current_spec_catalog import catalog
from current_spec_pending_contracts import MSET03_SCENARIOS, MSET04_SCENARIOS
from current_spec_pending_contracts import MSET06_SCENARIOS
from current_spec_pending_contracts import SETUP_MODEL_SCENARIOS, assertions_for
from current_spec_pending_contracts import mset03_classification, mset03_sample
from current_spec_pending_contracts import mset04_classification, mset04_sample
from current_spec_pending_contracts import sample_observation


class PendingContractTests(unittest.TestCase):
    def test_available_phases(self):
        for phase, size in ((4, 46), (5, 63), (6, 60)):
            path = f'vectors/0.10.0/current-spec-phase-{phase}-contracts.json'
            from pathlib import Path
            if (Path(__file__).resolve().parents[1] / path).exists():
                with self.subTest(phase=phase):
                    self.assertEqual(check(phase), size)

    def test_bridge_requires_explicit_host_adapter(self):
        from pathlib import Path
        path = Path(__file__).resolve().parents[1] / \
            'vectors/0.10.0/current-spec/mset-01-valid-channel-runtime.json'
        fixture = json.loads(path.read_text())
        request = {key: fixture[key] for key in
                   ('schema_version', 'spec_revision', 'id', 'track', 'input')}
        with patch.dict('os.environ', {'SAGE_CASE_ADAPTER': ''}):
            result = observe(json.dumps(request).encode())
        self.assertEqual(result['actual']['verdict'], 'UNSUPPORTED')
        case = next(row for row in catalog()[1]['cases']
                    if row['id'] == fixture['id'])
        good = {'case_id': fixture['id'], 'track': 'runtime',
                'observed_outcome': case['expected'],
                'assertions': {key: True for key in assertions_for(case['rule_id'])},
                'observer_effects': 0, 'subject_effects': 0}
        self.assertEqual(observe(json.dumps(request).encode(), good)['actual'],
                         fixture['expected'])
        changed = dict(good, observed_outcome='wrong outcome')
        self.assertEqual(observe(json.dumps(request).encode(), changed)
                         ['actual']['verdict'], 'REJECT')
        changed = dict(good, assertions={key: False for key in
                                         assertions_for(case['rule_id'])})
        self.assertEqual(observe(json.dumps(request).encode(), changed)
                         ['actual']['verdict'], 'REJECT')

    def test_undefined_media_type_does_not_gain_a_verdict(self):
        from pathlib import Path
        path = Path(__file__).resolve().parents[1] / \
            'vectors/0.10.0/current-spec/REG-08-N04-runtime.json'
        fixture = json.loads(path.read_text())
        request = {key: fixture[key] for key in
                   ('schema_version', 'spec_revision', 'id', 'track', 'input')}
        result = observe(json.dumps(request).encode(),
                         {'case_id': 'REG-08-N04', 'track': 'runtime'})
        self.assertEqual(result['actual']['verdict'], 'UNSUPPORTED')

    def test_setup_cases_use_state_transitions(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in SETUP_MODEL_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                if ident in MSET06_SCENARIOS:
                    self.assertNotIn('monotonic_deadline_checked',
                                     trace['assertions'])
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                trace['model_events'] = trace['model_events'][:-1]
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')

    def test_setup_model_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'setup-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in SETUP_MODEL_SCENARIOS:
                with self.subTest(ident=ident):
                    fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                          f'{ident}-runtime.json').read_text())
                    request = {key: fixture[key] for key in
                               ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                    case = cases[ident]
                    trace = sample_observation(case, rules[case['rule_id']],
                                               'runtime')
                    adapter.write_text('#!/usr/bin/env python3\n'
                                       'import json,sys\n'
                                       'json.load(sys.stdin)\n'
                                       f'print({json.dumps(json.dumps({"trace": trace}))})\n')
                    adapter.chmod(0o700)
                    result = subprocess.run(
                        [sys.executable, '-B',
                         str(root / 'scripts/current_spec_pending_bridge.py')],
                        input=json.dumps(request).encode(), capture_output=True,
                        env=environment, timeout=10, check=False)
                    self.assertEqual(result.returncode, 0,
                                     result.stderr.decode())
                    self.assertEqual(json.loads(result.stdout)['actual'],
                                     fixture['expected'])

    def test_initialize_response_cases_check_correlated_json(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MSET03_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertNotIn('initialize_correlation_checked',
                                 trace['assertions'])
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                replacement = ('mset-03-unsupported-version'
                               if ident == 'mset-03-initialize-success' else
                               'mset-03-initialize-success')
                trace['mcp_response'] = mset03_sample(replacement)
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')

    def test_initialize_response_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'initialize-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MSET03_SCENARIOS:
                with self.subTest(ident=ident):
                    fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                          f'{ident}-runtime.json').read_text())
                    request = {key: fixture[key] for key in
                               ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                    case = cases[ident]
                    trace = sample_observation(case, rules[case['rule_id']],
                                               'runtime')
                    adapter.write_text('#!/usr/bin/env python3\n'
                                       'import json,sys\n'
                                       'json.load(sys.stdin)\n'
                                       f'print({json.dumps(json.dumps({"trace": trace}))})\n')
                    adapter.chmod(0o700)
                    result = subprocess.run(
                        [sys.executable, '-B',
                         str(root / 'scripts/current_spec_pending_bridge.py')],
                        input=json.dumps(request).encode(), capture_output=True,
                        env=environment, timeout=10, check=False)
                    self.assertEqual(result.returncode, 0,
                                     result.stderr.decode())
                    self.assertEqual(json.loads(result.stdout)['actual'],
                                     fixture['expected'])

    def test_initialize_response_rejects_malformed_or_outer_failure(self):
        evidence = mset03_sample('mset-03-initialize-success')
        self.assertEqual(mset03_classification(evidence), 'valid')
        changed = dict(evidence, outer_success=False)
        self.assertEqual(mset03_classification(changed), 'outer_failure')
        changed = dict(evidence, response_outer_id=
                       '123e4567-e89b-42d3-a456-426614174002')
        self.assertEqual(mset03_classification(changed), 'wrong_request')
        changed = dict(evidence, response_json=
                       '{"jsonrpc":"2.0","jsonrpc":"2.0"}')
        self.assertEqual(mset03_classification(changed), 'malformed_response')
        changed = dict(evidence, inner_request_id='not-a-uuid')
        with self.assertRaises(ValueError):
            mset03_classification(changed)

    def test_notification_ack_cases_use_exact_marker_and_correlation(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MSET04_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertNotIn('notification_ack_checked', trace['assertions'])
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                replacement = ('mset-04-malformed-ack'
                               if ident == 'mset-04-notification-ack' else
                               'mset-04-notification-ack')
                trace['ack_evidence'] = mset04_sample(replacement)
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')

    def test_notification_ack_rejects_unexpected_output_and_json(self):
        evidence = mset04_sample('mset-04-notification-ack')
        self.assertEqual(mset04_classification(evidence), 'valid')
        changed = dict(evidence, guard_output_ids=['output-1'])
        self.assertEqual(mset04_classification(changed),
                         'unexpected_guard_output')
        changed = dict(evidence, notification_json=
                       '{"jsonrpc":"2.0","jsonrpc":"2.0"}')
        self.assertEqual(mset04_classification(changed),
                         'malformed_notification')
        changed = dict(evidence, ack_request_hash='b' * 64)
        self.assertEqual(mset04_classification(changed), 'malformed_ack')

    def test_notification_ack_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'ack-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MSET04_SCENARIOS:
                with self.subTest(ident=ident):
                    fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                          f'{ident}-runtime.json').read_text())
                    request = {key: fixture[key] for key in
                               ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                    case = cases[ident]
                    trace = sample_observation(case, rules[case['rule_id']],
                                               'runtime')
                    adapter.write_text('#!/usr/bin/env python3\n'
                                       'import json,sys\n'
                                       'json.load(sys.stdin)\n'
                                       f'print({json.dumps(json.dumps({"trace": trace}))})\n')
                    adapter.chmod(0o700)
                    result = subprocess.run(
                        [sys.executable, '-B',
                         str(root / 'scripts/current_spec_pending_bridge.py')],
                        input=json.dumps(request).encode(), capture_output=True,
                        env=environment, timeout=10, check=False)
                    self.assertEqual(result.returncode, 0,
                                     result.stderr.decode())
                    self.assertEqual(json.loads(result.stdout)['actual'],
                                     fixture['expected'])


if __name__ == '__main__':
    unittest.main()
