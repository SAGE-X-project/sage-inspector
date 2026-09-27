"""The primitive bridge must preserve case identity and hide expectations."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import current_spec_primitive_bridge as bridge
from current_spec_catalog import catalog


class PrimitiveBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.core = Path(self.temporary.name) / 'core.py'
        self.request = {'schema_version': 1, 'spec_revision': catalog()[0]['spec_revision'],
                        'id': 'JCS-01-N01', 'track': 'runtime',
                        'input': {'operation': 'jcs.canonicalize',
                                  'input': {'document_hex': '7b7d'}}}

    def make_core(self, wrong_id=False):
        program = ('#!/usr/bin/env python3\nimport json,sys\n'
                   'request=json.load(sys.stdin)\n'
                   "assert 'expected' not in request\n"
                   'print(json.dumps({"schema_version":1,"case_id":'
                   + ('"wrong"' if wrong_id else 'request["case_id"]') +
                   ',"verdict":"REJECT","output":{}}))\n')
        self.core.write_text(program)
        self.core.chmod(0o755)

    def test_bridge_maps_primitive_observation_without_effect_claim(self):
        self.make_core()
        response = bridge.observe(json.dumps(self.request).encode(), self.core)
        self.assertEqual(response['id'], 'JCS-01-N01')
        self.assertEqual(response['actual'], {'verdict': 'REJECT', 'output': {},
                                              'effects': {}})
        env = dict(os.environ, SAGE_CORE_ADAPTER=str(self.core))
        proc = subprocess.run([sys.executable, '-B', str(Path(bridge.__file__))],
                              input=json.dumps(self.request), capture_output=True,
                              text=True, env=env, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), response)

    def test_wrong_core_case_identity_is_rejected(self):
        self.make_core(wrong_id=True)
        with self.assertRaisesRegex(ValueError, 'core adapter response identity'):
            bridge.observe(json.dumps(self.request).encode(), self.core)

    def test_guard_integer_pair_requires_valid_control_and_rejected_candidate(self):
        self.core.write_text(
            '#!/usr/bin/env python3\nimport json,sys\n'
            'request=json.load(sys.stdin)\n'
            "control=request['case_id'].endswith('-control')\n"
            "print(json.dumps({'schema_version':1,'case_id':request['case_id'],"
            "'verdict':'ACCEPT' if control else 'REJECT',"
            "'output':{'valid':True} if control else {}}))\n")
        self.core.chmod(0o755)
        self.request['id'] = 'JCS-02-N01'
        self.request['input'] = {'operation': 'guard.integer_pair',
                                 'input': {'control': {'envelope_hex': 'aa'},
                                           'candidate': {'envelope_hex': 'bb'}}}
        actual = bridge.observe(json.dumps(self.request).encode(), self.core)['actual']
        self.assertEqual(actual, {'verdict': 'REJECT', 'output': {
            'control_verdict': 'ACCEPT', 'control_output': {'valid': True},
            'candidate_output': {}}, 'effects': {}})


if __name__ == '__main__':
    unittest.main()
