"""Controls for the adopted normative baseline lock."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import check_normative_baseline as checker


class NormativeBaselineTests(unittest.TestCase):
    def contract(self):
        return checker.load(checker.CONTRACT.read_text())

    def make_spec(self, contract, root):
        spec = contract['spec']
        record = {
            'status': spec['status'],
            'protocol_version': '0.10.0',
            'conformance': 'NOT_ESTABLISHED',
            'counts': {
                'requirements':45,'baseline_rule_groups':77,'binding_rule_groups':14,
                'total_rule_groups':91,'baseline_parent_cases':386,
                'binding_parent_cases':71,'total_parent_cases':457,
                'mandatory_binding_children':26,
                'historical_inspector_lifecycle_not_run':37},
            'normative_sha256': spec['artifacts']}
        for relative in spec['artifacts']:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative)
            spec['artifacts'][relative] = checker.sha(path.read_bytes())
            record['normative_sha256'][relative] = spec['artifacts'][relative]
        path = root / spec['adoption_record']
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, separators=(',', ':')))
        spec['adoption_record_sha256'] = checker.sha(path.read_bytes())
        return record

    def test_contract_fixes_order_and_separates_case_catalogs(self):
        value = checker.validate_contract(self.contract())
        self.assertEqual(value['case_model']['total_parent_cases'], 457)
        self.assertEqual(value['case_model']['separate_historical_lifecycle_cases'], 37)
        self.assertEqual(value['execution_order'][0], 'normative-provenance')
        self.assertEqual(value['execution_order'][-1], 'post-plan-errata-and-refactor')

    def test_reordered_work_and_promoted_conformance_are_rejected(self):
        for change in (
                lambda value: value['execution_order'].reverse(),
                lambda value: value.update(conformance='PASS'),
                lambda value: value['case_model'].update(total_parent_cases=494),
                lambda value: value['inspector'].update(
                    adoption_review_classification='CURRENT_NORMATIVE_REVIEW')):
            value = copy.deepcopy(self.contract())
            change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                checker.validate_contract(value)

    def test_spec_status_revision_and_artifact_drift_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = self.contract()
            self.make_spec(value, root)
            checker.validate_spec(value, root,
                                  revision_reader=lambda unused: value['spec']['revision'])
            adoption = root / value['spec']['adoption_record']
            data = json.loads(adoption.read_text())
            data['status'] = 'PROPOSAL_NOT_ADOPTED'
            adoption.write_text(json.dumps(data, separators=(',', ':')))
            value['spec']['adoption_record_sha256'] = checker.sha(adoption.read_bytes())
            with self.assertRaisesRegex(ValueError, 'adoption status'):
                checker.validate_spec(value, root,
                                      revision_reader=lambda unused: value['spec']['revision'])

    def test_core_revision_drift_is_rejected(self):
        value = self.contract()
        with self.assertRaisesRegex(ValueError, 'go core revision'):
            checker.validate_core(value, 'go', Path('.'),
                                  revision_reader=lambda unused: '0' * 40)


if __name__ == '__main__':
    unittest.main()

