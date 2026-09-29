"""Keep the control pair and unsupported URL boundary in the fixed suite."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import generate_did_prefix_suite as vectors


class DIDPrefixSuiteTests(unittest.TestCase):
    def test_control_and_mutations_are_exact(self):
        self.assertEqual(vectors.check()['cases'], 6)
        rows = json.loads((vectors.ROOT / vectors.OUTPUT).read_bytes())['cases']
        self.assertEqual([row['expected']['verdict'] for row in rows],
                         ['ACCEPT', 'REJECT', 'REJECT'] * 2)
        self.assertEqual([row['operation'] for row in rows],
                         ['sage.did.validate'] * 3 + ['sage.did-url.validate'] * 3)
        self.assertEqual(rows[0]['input']['did'], vectors.CANONICAL)
        self.assertEqual(rows[3]['input']['did_url'], vectors.CANONICAL + '#signing-1')

    def test_rewriting_expected_result_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ('verification/0.10.0/case-map.json',
                             vectors.OUTPUT):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(vectors.ROOT / relative, target)
            for name in ('manifest.json', 'traceability.json',
                         'additional-case-map.json'):
                relative = 'verification/0.10.0/latest-spec/' + name
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(vectors.ROOT / relative, target)
            path = root / vectors.OUTPUT
            suite = json.loads(path.read_bytes())
            suite['cases'][0]['expected']['verdict'] = 'REJECT'
            path.write_text(json.dumps(suite))
            with self.assertRaisesRegex(ValueError, 'suite bytes differ'):
                vectors.check(root)


if __name__ == '__main__':
    unittest.main()
