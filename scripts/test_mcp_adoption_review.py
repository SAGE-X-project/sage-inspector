"""Controls for the MCP adoption-readiness review."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import check_mcp_adoption_review as checker


class MCPAdoptionReviewTests(unittest.TestCase):
    def value(self):
        return checker.load(checker.CONTRACT.read_text())

    def proposal(self):
        return (checker.BASE/'consolidated.md').read_text()

    def test_review_retains_blocked_unadopted_status(self):
        value = checker.validate_contract(self.value(), self.proposal())
        self.assertEqual(value['finding_counts'],
                         {'HIGH':4,'MEDIUM':2,'OPEN':5,'PENDING_EXTERNAL':1})
        self.assertEqual(value['adoption_readiness'], 'BLOCKED')
        self.assertEqual(value['external_review'], 'NOT_PERFORMED')
        self.assertEqual({row['id'] for row in value['findings']}, checker.EXPECTED_IDS)

    def test_status_promotion_and_missing_findings_are_rejected(self):
        for change in (
                lambda value: value.update(adoption='ADOPTED'),
                lambda value: value.update(external_review='COMPLETE'),
                lambda value: value.update(adoption_readiness='READY'),
                lambda value: value['findings'].pop()):
            value = copy.deepcopy(self.value())
            change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                checker.validate_contract(value, self.proposal())

    def test_anchor_drift_is_rejected(self):
        value = self.value()
        value['findings'][0]['anchors'][0] = 'A rule that is not in the proposal.'
        with self.assertRaisesRegex(ValueError, 'finding anchor'):
            checker.validate_contract(value, self.proposal())

    def test_evidence_contract_drift_is_rejected(self):
        value = self.value()
        value['source']['aggregate_evidence_contract_sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'aggregate evidence binding'):
            checker.validate_contract(value, self.proposal())

    def test_cli_preserves_contract_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)/'review'
            command = [sys.executable,'-B',str(checker.ROOT/'scripts/check_mcp_adoption_review.py'),
                       '--output',str(output)]
            result = subprocess.run(command,cwd=checker.ROOT,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            report=json.loads((output/'report.json').read_text())
            self.assertEqual(report['status'],'REVIEW_CHECKED')
            self.assertEqual(report['adoption_readiness'],'BLOCKED')
            self.assertEqual((output/'contract.json').read_bytes(),checker.CONTRACT.read_bytes())
            result=subprocess.run(command,cwd=checker.ROOT,capture_output=True,text=True,timeout=15)
            self.assertNotEqual(result.returncode,0)


if __name__ == '__main__':
    unittest.main()
