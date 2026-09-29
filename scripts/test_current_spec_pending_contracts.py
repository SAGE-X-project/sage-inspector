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
from current_spec_pending_contracts import MSET06_SCENARIOS, assertions_for
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

    def test_setup_deadline_cases_use_state_transitions(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        for ident in MSET06_SCENARIOS:
            with self.subTest(ident=ident):
                fixture = json.loads((root / 'vectors/0.10.0/current-spec' /
                                      f'{ident}-runtime.json').read_text())
                request = {key: fixture[key] for key in
                           ('schema_version', 'spec_revision', 'id', 'track', 'input')}
                case = cases[ident]
                trace = sample_observation(case, rules[case['rule_id']], 'runtime')
                self.assertNotIn('monotonic_deadline_checked', trace['assertions'])
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual'], fixture['expected'])
                trace['model_events'] = trace['model_events'][:-1]
                self.assertEqual(observe(json.dumps(request).encode(), trace)
                                 ['actual']['verdict'], 'REJECT')

    def test_setup_deadline_bridge_runs_local_adapter(self):
        root = Path(__file__).resolve().parents[1]
        source = catalog()[1]
        cases = {row['id']: row for row in source['cases']}
        rules = {row['id']: row for row in source['rules']}
        with tempfile.TemporaryDirectory() as temporary:
            adapter = Path(temporary) / 'setup-observer'
            environment = dict(os.environ, SAGE_CASE_ADAPTER=str(adapter))
            for ident in MSET06_SCENARIOS:
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
