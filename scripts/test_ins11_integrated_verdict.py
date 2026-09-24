"""Prevent a complete INS-11 claim from scoped implementation evidence."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import check_ins11_integrated_verdict as verdict


class IntegratedVerdictTests(unittest.TestCase):
    def test_saved_verdict_and_cli(self):
        report = verdict.check_saved()
        self.assertEqual(report['ins11'], 'INCOMPLETE')
        self.assertEqual(report['unresolved']['live_registry'], 'NOT_RUN')
        self.assertEqual(report['unresolved']['deployed_host'], 'NOT_RUN')
        result = subprocess.run(
            [sys.executable, '-B', str(Path(verdict.__file__))],
            cwd=verdict.ROOT, capture_output=True, text=True, timeout=20,
            check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('INS-11 INCOMPLETE', result.stdout)

    def test_final_claim_cannot_be_promoted(self):
        report = verdict.build()
        report['ins11'] = 'COMPLETE'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.json'
            path.write_text(json.dumps(report) + '\n')
            with self.assertRaisesRegex(ValueError, 'verdict drift'):
                verdict.check_saved(path)

    def test_binding_revision_cannot_be_relabelled(self):
        original = verdict.read

        def changed(relative):
            value, digest = original(relative)
            if relative.endswith('/mcp-binding.json'):
                value = copy.deepcopy(value)
                value['mandatory_children']['go']['revision'] = (
                    '2fb4755ba38d1c90adea5089402fcc6b8981fd71')
            return value, digest

        with mock.patch.object(verdict, 'read', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'child/revision'):
                verdict.build()

    def test_missing_registry_cannot_become_pass(self):
        real = verdict.check_registry()
        changed = dict(real, live_chain_verification='PASS')
        with mock.patch.object(verdict, 'check_registry', return_value=changed):
            with self.assertRaisesRegex(ValueError, 'unresolved deployment'):
                verdict.build()


if __name__ == '__main__':
    unittest.main()
