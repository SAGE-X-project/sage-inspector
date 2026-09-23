"""Controls for complete MSET evidence classification."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import check_mcp_setup_cases as checker


class SetupCaseEvidenceTests(unittest.TestCase):
    def test_contract_covers_every_mset_case_without_conformance_promotion(self):
        value=checker.validate_contract(copy.deepcopy(checker.SETUP_VALUE))
        self.assertEqual(len(value['assessments']),58)
        self.assertEqual({row['evidence_kind'] for row in value['assessments']},{'core','interop','policy'})
        self.assertEqual(sum(row['evidence_kind']=='core' for row in value['assessments']),53)
        self.assertEqual(value['case_counts'],{'PASS':58,'PARTIAL':0,'NOT_RUN':0})
        self.assertEqual(value['adoption'],'PROPOSAL_NOT_ADOPTED')
        self.assertEqual(value['conformance'],'NOT_ESTABLISHED')

    def test_changed_case_mapping_is_rejected(self):
        value=copy.deepcopy(checker.SETUP_VALUE)
        row=next(row for row in value['assessments'] if row['evidence_kind']=='core')
        row['requirements'][0]['test']='unrelated_test'
        with self.assertRaisesRegex(ValueError,'test mapping'):
            checker.validate_contract(value)

    def test_policy_and_interop_cases_cannot_claim_core_evidence(self):
        for kind in ('policy','interop'):
            value=copy.deepcopy(checker.SETUP_VALUE)
            row=next(row for row in value['assessments'] if row['evidence_kind']==kind)
            row['requirements']=[{'language':'go','test':'TestMCPAuthenticatedSetupRuntime'}]
            with self.assertRaisesRegex(ValueError,'non-core requirements'):
                checker.validate_contract(value)

    def test_complete_interop_matrix_and_restart_are_required(self):
        report={'kind':'mcp-native-protected-interop','status':'PASS','protected_dispatch':'PASS',
                'completed_recovery':'SELECTED_ASSERTIONS_PASS',
                'subjects':{language:{'revision':pin} for language,pin in checker.PINS.items()},
                'pairs':[{'pair':pair,'status':'PASS','frames':10,'independent_signatures':13,
                          'protected_exchanges':1,'effects':1,'terminal_records':1,
                          'setup_signature_checks':9,'protected_signature_checks':4,
                          'execution_transitions':['RESERVED','EXECUTING','COMPLETED'],
                          'decrypted_records':8,'decrypted_setup_exchanges':3,
                          'decrypted_protected_exchanges':1,'decrypted_result_signatures':1,
                          'peer_secret_match':True,'exit_codes':[0,0]}
                         for pair in checker.SETUP_VALUE['interop']['required_pairs']],
                'restart':[{'pair':pair,'restart_mode':mode,'status':'PASS'}
                           for mode in checker.SETUP_VALUE['interop']['restart_modes']
                           for pair in checker.SETUP_VALUE['interop']['required_pairs']]}
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp); (path/'report.json').write_text(json.dumps(report))
            self.assertEqual(checker.validate_interop(path)['status'],'PASS')
            report['restart'].pop(); (path/'report.json').write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError,'restart inventory'):
                checker.validate_interop(path)

    def test_policy_cases_are_bound_to_the_consolidated_proposal(self):
        text=(checker.CATALOG_BASE/'consolidated.md').read_text()
        self.assertIn('unadopted',checker.validate_policy('mset-08-proposal-scope',text,{'NOT_RUN':71}))
        self.assertIn('excluded',checker.validate_policy('mset-08-http-not-defined',text,{'NOT_RUN':71}))
        self.assertIn('71 NOT_RUN',checker.validate_policy('mset-08-historical-evidence',text,{'NOT_RUN':71}))
        with self.assertRaisesRegex(ValueError,'HTTP exclusion'):
            checker.validate_policy('mset-08-http-not-defined',text.replace('It does not define chapter 08 HTTP','It defines chapter 08 HTTP'),{'NOT_RUN':71})


if __name__ == '__main__':
    unittest.main()
