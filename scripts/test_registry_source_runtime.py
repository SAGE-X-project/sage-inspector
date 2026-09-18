"""Safe CLI runtime tests: owned JSON files, no network or transaction execution."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_registry_source010 import BINDING, BUNDLE, fixture
from inspect_registry_source010 import ROOT, sha


class RuntimeTests(unittest.TestCase):
    def test_cli_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corrupted = root/'corrupt.json'
            _, _, bundle = fixture()
            bundle['observations'][0]['keys_block_hash'] = '00'*32
            corrupted.write_text(json.dumps(bundle))
            duplicate = root/'duplicate.json'
            duplicate.write_text('{"schema_version":1,"schema_version":1}')
            cases = (
                ('no-binding', [], 3, 'NOT_RUN'),
                ('no-observation', ['--binding', str(BINDING)], 3, 'NOT_RUN'),
                ('valid', ['--binding', str(BINDING), '--observations', str(BUNDLE)], 0, 'EVIDENCE_VALIDATED'),
                ('mixed-block', ['--binding', str(BINDING), '--observations', str(corrupted)], 1, 'FAIL'),
                ('missing-binding', ['--observations', str(BUNDLE)], 1, 'FAIL'),
                ('duplicate-json', ['--binding', str(duplicate)], 1, 'FAIL'),
                ('missing-file', ['--binding', str(root/'absent.json')], 1, 'FAIL'),
            )
            for name, args, code, status in cases:
                with self.subTest(case=name):
                    output = root/name
                    command = [sys.executable, str(ROOT/'scripts/inspect_registry_source010.py'),
                               '--output', str(output), *args]
                    process = subprocess.run(command, capture_output=True, timeout=10)
                    self.assertEqual(process.returncode, code, process.stderr)
                    report = json.loads((output/'report.json').read_bytes())
                    self.assertEqual(report['status'], status)
                    self.assertEqual(report['live_chain_verification'], 'NOT_RUN')
                    self.assertEqual(report['conformance'], 'NOT_ESTABLISHED')
                    self.assertFalse(report['actual_core_execution'])
                    for file, digest in report['files'].items():
                        self.assertEqual(sha((output/file).read_bytes()), digest)
                    print(json.dumps(dict(case=name, exit_code=process.returncode, stdout=process.stdout.decode(),
                                          stderr=process.stderr.decode(), report=report)), flush=True)
                    before = (output/'report.json').read_bytes()
                    repeated = subprocess.run(command, capture_output=True, timeout=10)
                    self.assertEqual(repeated.returncode, 2)
                    self.assertEqual((output/'report.json').read_bytes(), before)
                    print(name + ': exit/status/raw hashes/scope/output preservation verified', flush=True)


if __name__ == '__main__':
    unittest.main()
