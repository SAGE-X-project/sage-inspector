"""Check all new case contracts stay tied to the pinned normative cases."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import latest_spec_case_bindings as checker
from latest_spec_catalog import NEW_IDS


class LatestSpecBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in checker.rendered():
            source = checker.ROOT / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        for name in ('manifest.json', 'traceability.json', 'additional-case-map.json'):
            relative = checker.LATEST_BASE + '/' + name
            source = checker.ROOT / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        historical = 'verification/0.10.0/case-map.json'
        target = self.root / historical
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(checker.ROOT / historical, target)

    def test_every_new_case_has_one_source_exact_partial_binding(self):
        self.assertEqual(checker.check(self.root)['cases'], 8)
        contract = json.loads((self.root / checker.BINDINGS).read_bytes())
        self.assertEqual({row['id'] for row in contract['bindings']}, NEW_IDS)
        self.assertTrue(all(row['coverage'] == 'partial' for row in contract['bindings']))

    def test_fixture_change_fails_exact_source_check(self):
        path = self.root / checker.VECTOR_BASE / 'msca-http-no-substitution.json'
        fixture = json.loads(path.read_bytes())
        fixture['input']['normative_expected'] = 'accept any alternate key'
        path.write_text(json.dumps(fixture))
        with self.assertRaisesRegex(ValueError, 'latest case binding differs'):
            checker.check(self.root)

    def test_missing_case_binding_fails(self):
        path = self.root / checker.BINDINGS
        contract = json.loads(path.read_bytes())
        contract['bindings'] = contract['bindings'][:-1]
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, 'latest case binding differs'):
            checker.check(self.root)

    def test_partial_contract_cannot_be_relabelled_complete(self):
        path = self.root / checker.BINDINGS
        contract = json.loads(path.read_bytes())
        contract['bindings'][0]['coverage'] = 'complete'
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, 'latest case binding differs'):
            checker.check(self.root)


if __name__ == '__main__':
    unittest.main()
