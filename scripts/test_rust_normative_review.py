"""Controls for the Rust normative implementation review."""
import copy
from pathlib import Path
import tempfile
import unittest

import check_rust_normative_review as checker


class RustNormativeReviewTests(unittest.TestCase):
    def value(self):
        return checker.load(checker.CONTRACT.read_text())

    def test_contract_retains_complete_direct_status_and_all_children(self):
        value = checker.validate_contract(self.value())
        self.assertEqual(value['counts'], {'DIRECT':26,'PARTIAL':0,'MISSING':0})
        self.assertEqual(len(value['children']), 26)
        self.assertEqual(value['review_status'], 'COMPLETE')

    def test_status_promotion_reordering_and_false_evidence_are_rejected(self):
        changes = (
            lambda value: value.update(review_status='INCOMPLETE'),
            lambda value: value.update(conformance='PASS'),
            lambda value: value['children'].pop(),
            lambda value: value['children'][-1].update(tests=[]),
        )
        for change in changes:
            value = copy.deepcopy(self.value())
            change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                checker.validate_contract(value)

    def test_adopted_child_inventory_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'verification/traceability.json'
            path.parent.mkdir(parents=True)
            value = self.value()
            trace = {
                'binding_adoption': {
                    'status':'ADOPTED_NORMATIVE_DESIGN','parent_cases':71,
                    'mandatory_child_assertions':26},
                'mandatory_subscenarios': [
                    {'id':row['id']} for row in value['children'][:-1]] +
                    [{'id':'replacement-child'}]}
            path.write_text(__import__('json').dumps(trace))
            with self.assertRaisesRegex(ValueError, 'mandatory child inventory'):
                checker.validate_spec(value, root,
                                      revision_reader=lambda unused: value['spec_revision'])

    def test_missing_rust_test_definition_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'src/sample.rs'
            path.parent.mkdir(parents=True)
            path.write_text('fn unrelated() {}\n')
            with self.assertRaisesRegex(ValueError, 'missing Rust test definition'):
                checker.validate_rust(self.value(), root,
                                    revision_reader=lambda unused: self.value()['rust_revision'])


if __name__ == '__main__':
    unittest.main()
