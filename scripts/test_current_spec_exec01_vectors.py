"""Synthetic capability examples remain distinct from live deployment proof."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import check_current_spec_exec01_vectors as checker
from inspect_exec01_boundary import inspect


class Exec01Tests(unittest.TestCase):
    def test_pinned_vectors(self):
        self.assertEqual(checker.check(), 5)
        suite = checker.load((checker.ROOT / checker.SOURCE).read_bytes())
        for row in suite['cases']:
            verdict = 'REJECT' if inspect(row['input']) else 'ACCEPT'
            self.assertEqual(verdict, row['expected']['verdict'], row['id'])

    def test_unenumerated_bypasses_and_server_privilege(self):
        good = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        for change in (
            lambda item: item['effect_paths']['network'].update(
                bypass_credentials_exposed=True),
            lambda item: item['effect_paths'].pop('subagent'),
            lambda item: item['server'].update(tool_has_host_privilege=True),
            lambda item: item['protected_assets']['policy']['writers'].append('mcp'),
            lambda item: item['hook']['writers'].append('plugin'),
        ):
            candidate = copy.deepcopy(good)
            change(candidate)
            self.assertTrue(inspect(candidate))

    def test_bounded_cli_reports_no_deployment_conformance(self):
        candidate = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'boundary.json'
            path.write_text(json.dumps(candidate))
            run = subprocess.run([sys.executable, '-B',
                                  str(checker.ROOT / 'scripts/inspect_exec01_boundary.py'),
                                  '--input', str(path)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(run.stdout)
            self.assertEqual(report['verdict'], 'ACCEPT')
            self.assertEqual(report['deployment_conformance'], 'NOT_ESTABLISHED')


if __name__ == '__main__':
    unittest.main()
