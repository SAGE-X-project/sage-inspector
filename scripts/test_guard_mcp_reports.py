"""Offline controls prevent carriage and proof failures from becoming accepted output."""
import copy
import json
import unittest
from test_guard_mcp010 import ROOT, check_answer, wire

class MCPReports(unittest.TestCase):
    def setUp(self):
        self.case=json.loads((ROOT/'vectors/0.10.0/guard-mcp.json').read_text())['cases'][0]
        self.answer=dict(schema_version=1,case_id=self.case['id'],verdict='ACCEPT',output=dict(status='completed',success=True,error='',wire_hex=self.case['input']['wire_hex']))
    def test_valid(self):check_answer(self.case,self.answer)
    def test_reject_invalid_observations(self):
        for key,value in [('success',False),('error','unavailable'),('status','pending'),('wire_hex',b'{}'.hex())]:
            a=copy.deepcopy(self.answer);a['output'][key]=value
            with self.assertRaises(ValueError):check_answer(self.case,a)
    def test_reject_unsigned_annotation(self):
        a=copy.deepcopy(self.answer);v=json.loads(bytes.fromhex(a['output']['wire_hex']));v['_meta']={'note':'unsigned'};a['output']['wire_hex']=wire(v).encode().hex()
        with self.assertRaises(ValueError):check_answer(self.case,a)
    def test_reject_unverified_output(self):
        c=copy.deepcopy(self.case);c['accept']=False;a=copy.deepcopy(self.answer);a['verdict']='REJECT'
        with self.assertRaises(ValueError):check_answer(c,a)
    def test_reject_wrong_identity(self):
        a=copy.deepcopy(self.answer);a['case_id']='other'
        with self.assertRaises(ValueError):check_answer(self.case,a)
if __name__=='__main__':unittest.main()
