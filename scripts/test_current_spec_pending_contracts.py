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
from current_spec_pending_contracts import MSET01_SCENARIOS, MSET02_SCENARIOS
from current_spec_pending_contracts import MSET03_SCENARIOS
from current_spec_pending_contracts import MSET04_SCENARIOS
from current_spec_pending_contracts import MSET05_SCENARIOS, MSET06_SCENARIOS
from current_spec_pending_contracts import MSET07_SCENARIOS
from current_spec_pending_contracts import MSET08_SCENARIOS
from current_spec_pending_contracts import MERRATA_CONFIG_SCENARIOS
from current_spec_pending_contracts import MOWN01_SCENARIOS, mown01_check
from current_spec_pending_contracts import MOWN05_ROLES, mown05_check
from current_spec_pending_contracts import mown05_sample
from current_spec_pending_contracts import MOWN_MODEL_SCENARIOS, owner_model_check
from current_spec_owner_surface import SAMPLES as MOWN02_SAMPLES
from current_spec_owner_surface import check as mown02_check
from current_spec_owner_surface import sample as mown02_sample
from current_spec_owner_children import IDS as MOWN06_CHILD_IDS
from current_spec_owner_children import GROUPS as MOWN06_GROUPS
from current_spec_owner_children import check as mown06_check
from current_spec_owner_children import sample as mown06_sample
from current_spec_pending_contracts import SETUP_MODEL_SCENARIOS
from current_spec_pending_contracts import mset01_classification, mset01_sample
from current_spec_pending_contracts import mset02_classification, mset02_sample
from current_spec_pending_contracts import mset03_classification, mset03_sample
from current_spec_pending_contracts import mset04_classification, mset04_sample
from current_spec_pending_contracts import mset05_classification, mset05_sample
from current_spec_pending_contracts import mset07_classification, mset07_sample
from current_spec_pending_contracts import mset08_classification, mset08_sample
from current_spec_pending_contracts import merrata_config_classification
from current_spec_pending_contracts import merrata_config_sample
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
        rule = next(row for row in catalog()[1]['rules']
                    if row['id'] == case['rule_id'])
        good = sample_observation(case, rule, 'runtime')
        self.assertEqual(observe(json.dumps(request).encode(), good)['actual'],
                         fixture['expected'])
        changed = dict(good, observed_outcome='wrong outcome')
        self.assertEqual(observe(json.dumps(request).encode(), changed)
                         ['actual']['verdict'], 'REJECT')
        changed = dict(good, channel_evidence=mset01_sample('mset-01-wrong-owner'))
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

    def test_discovery_cases_check_complete_descriptor(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MSET05_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertNotIn('descriptor_and_gate_checked',
                                 trace['assertions'])
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                replacement = ('mset-05-schema-replacement'
                               if ident == 'mset-05-discovery-success' else
                               'mset-05-discovery-success')
                trace['discovery_evidence'] = mset05_sample(replacement)
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')

    def test_discovery_rejects_cursor_and_wrong_correlation(self):
        evidence = mset05_sample('mset-05-discovery-success')
        self.assertEqual(mset05_classification(evidence), 'valid')
        response = json.loads(evidence['response_json'])
        response['result']['nextCursor'] = 'next'
        changed = dict(evidence, response_json=json.dumps(response))
        self.assertEqual(mset05_classification(changed), 'malformed_listing')
        response['result'].pop('nextCursor')
        response['id'] = '123e4567-e89b-42d3-a456-426614174004'
        changed = dict(evidence, response_json=json.dumps(response))
        self.assertEqual(mset05_classification(changed), 'malformed_listing')

    def test_discovery_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'discovery-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MSET05_SCENARIOS:
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

    def test_channel_owner_cases_bind_session_and_active_key(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MSET01_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertEqual(trace['assertions'], {})
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                replacement = ('mset-01-revoked-key'
                               if ident == 'mset-01-valid-channel' else
                               'mset-01-valid-channel')
                trace['channel_evidence'] = mset01_sample(replacement)
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')
        evidence = mset01_sample('mset-01-valid-channel')
        changed = dict(evidence, authenticated_handshake_ids=[])
        self.assertEqual(mset01_classification(changed),
                         'unauthenticated_channel')

    def test_channel_owner_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'channel-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MSET01_SCENARIOS:
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

    def test_carriage_cases_check_exact_bytes_and_limits(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MSET02_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                replacement = ('mset-02-size-boundary'
                               if ident == 'mset-02-exact-bytes' else
                               'mset-02-exact-bytes')
                trace['carriage_evidence'] = mset02_sample(replacement)
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')
        evidence = mset02_sample('mset-02-exact-bytes')
        changed = dict(evidence, received_plaintext_b64=
                       mset02_sample('mset-02-json-duplicates')
                       ['received_plaintext_b64'])
        self.assertEqual(mset02_classification(changed), 'invalid_json')

    def test_carriage_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'carriage-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MSET02_SCENARIOS:
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

    def test_reconnect_cases_preserve_durable_identity(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MSET07_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertNotIn('fresh_owner_and_durable_state_checked',
                                 trace['assertions'])
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                replacement = ('mset-07-missing-ledger'
                               if ident == 'mset-07-fresh-reconnect' else
                               'mset-07-fresh-reconnect')
                trace['reconnect_evidence'] = mset07_sample(replacement)
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')
        evidence = mset07_sample('mset-07-terminal-preserved')
        changed = dict(evidence, terminal_digest_after='b' * 64)
        self.assertEqual(mset07_classification(changed), 'terminal_changed')
        changed = mset07_sample('mset-07-missing-ledger')
        changed['empty_ledger_created'] = True
        self.assertEqual(mset07_classification(changed),
                         'ledger_recreated_or_dispatched')

    def test_reconnect_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'reconnect-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MSET07_SCENARIOS:
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

    def test_adoption_scope_cases_reject_unsupported_claims(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MSET08_SCENARIOS:
            for track in ('runtime', 'document_review'):
                with self.subTest(ident=ident, track=track):
                    fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                          f'{ident}-{track}.json').read_text())
                    request = {key: fixture[key] for key in
                               ('schema_version', 'spec_revision', 'id',
                                'track', 'input')}
                    case = cases[ident]
                    trace = sample_observation(case, rules[case['rule_id']], track)
                    self.assertEqual(trace['assertions'], {})
                    self.assertEqual(observe(json.dumps(request).encode(), trace)
                                     ['actual'], fixture['expected'])
                    changed = dict(trace, scope_evidence=mset08_sample(
                        'mset-08-historical-evidence' if
                        ident == 'mset-08-proposal-scope' else
                        'mset-08-proposal-scope'))
                    self.assertEqual(observe(json.dumps(request).encode(), changed)
                                     ['actual']['verdict'], 'REJECT')
        changed = mset08_sample('mset-08-http-not-defined')
        changed['fallback_effect_ids'] = ['effect-1']
        self.assertEqual(mset08_classification(changed),
                         'unjustified_scope_or_promotion')

    def test_adoption_scope_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'scope-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MSET08_SCENARIOS:
                for track in ('runtime', 'document_review'):
                    with self.subTest(ident=ident, track=track):
                        fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                              f'{ident}-{track}.json').read_text())
                        request = {key: fixture[key] for key in
                                   ('schema_version', 'spec_revision', 'id',
                                    'track', 'input')}
                        case = cases[ident]
                        trace = sample_observation(case, rules[case['rule_id']],
                                                   track)
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

    def test_trusted_configuration_cases_validate_complete_binding(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MERRATA_CONFIG_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                replacement = ('merrata-config-reject'
                               if ident == 'merrata-config-valid' else
                               'merrata-config-valid')
                trace['configuration_evidence'] = merrata_config_sample(replacement)
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')
        changed = merrata_config_sample('merrata-config-change')
        changed['owner_state'] = 'READY'
        self.assertEqual(merrata_config_classification(changed),
                         'unsafe_configuration_change')
        changed = merrata_config_sample('merrata-config-valid')
        changed['peer_digest'] = 'sha256-jcs:wrong'
        self.assertEqual(merrata_config_classification(changed),
                         'invalid_configuration')

    def test_trusted_configuration_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'configuration-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MERRATA_CONFIG_SCENARIOS:
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

    def test_complete_message_limit_cases_use_measured_state(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        mutations = {
            'madd-plaintext-boundary': ('over_dispatched', True),
            'madd-record-boundary': ('oversize_processed', True),
            'madd-wire-boundary': ('oversize_processed', True),
            'madd-utf8-and-escapes': ('counted_bytes', 1),
            'madd-result-representations': ('complete_rejected', False),
            'madd-post-effect-oversize': ('terminal_after', 'b' * 64),
            'madd-post-reservation-size-failure': ('sent_count', 1),
            'madd-inner-size-replay': ('dispatch_count', 1),
        }
        for ident in MOWN01_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertEqual(trace['assertions'], {})
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                field, value = mutations[ident]
                trace['size_evidence'][field] = value
                self.assertFalse(mown01_check(ident, trace['size_evidence']))
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')

    def test_complete_message_limit_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'size-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MOWN01_SCENARIOS:
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

    def test_signing_roles_reject_algorithm_and_key_substitution(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MOWN05_ROLES:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertEqual(trace['assertions'], {})
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                if ident == 'mres-missing-signing-key':
                    trace['signature_evidence']['fallback_used'] = True
                else:
                    trace['signature_evidence']['attempts'][1]['result'] = 'CONTINUE'
                self.assertFalse(mown05_check(ident, trace['signature_evidence']))
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')
        changed = mown05_sample('mres-signature-carriage')
        changed['hpke_kem'] = 'Ed25519'
        self.assertFalse(mown05_check('mres-signature-carriage', changed))

    def test_signing_role_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'signature-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MOWN05_ROLES:
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

    def test_owner_admission_cases_use_state_transitions(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MOWN_MODEL_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertEqual(trace['assertions'], {})
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                trace['owner_events'] = trace['owner_events'][:-1]
                self.assertFalse(owner_model_check(ident, trace['owner_events']))
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')

    def test_owner_admission_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'owner-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MOWN_MODEL_SCENARIOS:
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

    def test_owner_publication_cases_reject_changed_decisive_evidence(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        mutations = {
            'madd-mutable-buffer': ('handoff_sha256', 'b' * 64),
            'madd-synchronous-completion': ('publication_seq', 1),
            'madd-duplicate-completion': ('output_count', 2),
            'madd-old-incarnation': ('new_owner_mutations', 1),
            'madd-bounded-cancellation': ('before_admission_effects', 1),
            'madd-history-capacity': ('next_id_accepted', True),
            'madd-close-before-handoff': ('queue_admissions', 1),
            'madd-close-after-handoff': ('admission_retained', False),
            'madd-cross-language-setup': ('independent_implementations', 1),
            'madd-restart-consumption': ('redeliveries', 1),
            'merrata-local-single-flight': ('second_signatures', 1),
            'merrata-server-overlap': ('second_queue_insertions', 1),
            'merrata-deferred-frame': ('deferred_auth_seq', 1),
            'merrata-pending-followup': ('next_inner_id', 'inner-1'),
            'merrata-deadline-close': ('redispatches', 1),
            'merrata-shared-owners': ('extra_work_admitted', 1),
        }
        self.assertEqual(set(mutations), set(MOWN02_SAMPLES))
        for ident in MOWN02_SAMPLES:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertEqual(trace['assertions'], {})
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                field, value = mutations[ident]
                trace['owner_surface_evidence'][field] = value
                self.assertFalse(mown02_check(ident,
                                             trace['owner_surface_evidence']))
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')

    def test_owner_publication_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'publication-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MOWN02_SAMPLES:
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

    def test_mandatory_owner_children_reject_changed_security_facts(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        children = {row['id']: row for row in source['mandatory_subscenarios']}
        rule = next(row for row in source['rules'] if row['id'] == 'MOWN-06')
        def mutate(ident, evidence):
            category = next(name for name, members in MOWN06_GROUPS.items()
                            if ident in members)
            changes = {
                'generation': ('queue_admissions', 1),
                'queue_failure': ('visible_queue_entries', 1),
                'shared_close': ('owner_a_effects', 1),
                'fence': ('queue_admissions', 1),
                'write_failure': ('scope_available', True),
                'recovery_failure': ('writer_ready', True),
                'pool': ('new_slots_before_completion', 1),
                'history': ('next_id_admitted', True),
                'record_limit': ('owner_closed', False),
            }
            if category in ('observation', 'expiry'):
                field = 'queue_admissions'
                value = 0 if evidence[field] else 1
            elif category == 'retirement':
                field = 'entry_cancelled'
                value = not evidence[field]
            elif category == 'scheduler':
                field, value = (('worker_claims', 1)
                                if ident == 'scheduler-cancel-race' else
                                ('extra_work_admitted', 1))
            else:
                field, value = changes[category]
            evidence[field] = value
        self.assertEqual(len(MOWN06_CHILD_IDS), 26)
        for ident in MOWN06_CHILD_IDS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                trace = sample_observation(children[ident], rule, 'runtime')
                self.assertEqual(trace['assertions'], {})
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                mutate(ident, trace['child_evidence'])
                self.assertFalse(mown06_check(ident, trace['child_evidence']))
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')

    def test_mandatory_owner_children_run_through_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        children = {row['id']: row for row in source['mandatory_subscenarios']}
        rule = next(row for row in source['rules'] if row['id'] == 'MOWN-06')
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'child-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MOWN06_CHILD_IDS:
                with self.subTest(ident=ident):
                    fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                          f'{ident}-runtime.json').read_text())
                    request = {key: fixture[key] for key in
                               ('schema_version', 'spec_revision', 'id',
                                'track', 'input')}
                    trace = sample_observation(children[ident], rule, 'runtime')
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

    def test_owner_observation_types_are_exact(self):
        owner = mown02_sample('madd-history-capacity')
        owner['retained_ids'] = True
        self.assertFalse(mown02_check('madd-history-capacity', owner))
        child = mown06_sample('owner-history-1024')
        child['retained_ids'] = True
        self.assertFalse(mown06_check('owner-history-1024', child))


if __name__ == '__main__':
    unittest.main()
