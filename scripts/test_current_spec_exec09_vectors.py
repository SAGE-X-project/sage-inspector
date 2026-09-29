"""A signature or file hash alone cannot support broader security claims."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import check_current_spec_exec09_vectors as checker
from inspect_guard_claims import inspect


class Exec09ClaimTests(unittest.TestCase):
    def test_pinned_claim_declarations(self):
        self.assertEqual(checker.check(), 3)
        suite = checker.load((checker.ROOT / checker.SOURCE).read_bytes())
        for row in suite['cases']:
            verdict = 'REJECT' if inspect(row['input']) else 'ACCEPT'
            self.assertEqual(verdict, row['expected']['verdict'], row['id'])

    def test_cli_never_claims_document_conformance(self):
        claim = checker.load((checker.ROOT / checker.SOURCE).read_bytes())['cases'][0]['input']
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'claim.json'
            path.write_text(json.dumps(claim))
            result = subprocess.run([sys.executable, '-B',
                                     str(checker.ROOT / 'scripts/inspect_guard_claims.py'),
                                     '--input', str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['document_conformance'],
                             'NOT_ESTABLISHED')


if __name__ == '__main__':
    unittest.main()
