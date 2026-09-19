"""Offline client evidence changes; no network or host bypass code."""
import copy
import json
import unittest
from test_guard_client010 import ROOT, HEADER, case_commands, verify_rows, verify_observations, recovery

class ClientEvidence(unittest.TestCase):
    def setUp(self):self.v=json.loads((ROOT/'vectors/0.10.0/guard-client.json').read_bytes())
    def test_exact_scenarios(self):
        self.assertEqual(len(self.v['cases']),19)
        for case in self.v['cases']:
            _,wants,rows=case_commands(self.v,case)
            verify_observations(wants,wants)
            verify_rows(HEADER+b''.join(json.dumps(r).encode()+b'\n' for r in rows),rows)
    def test_missing_and_duplicate_output(self):
        _,wants,_=case_commands(self.v,self.v['cases'][0])
        with self.assertRaises(ValueError):verify_observations(wants[:-1],wants)
        changed=copy.deepcopy(wants);changed[0]['output_hex']='7b7d'
        with self.assertRaises(ValueError):verify_observations(changed,wants)
        changed=copy.deepcopy(wants);changed[0]['handoffs']=1
        with self.assertRaises(ValueError):verify_observations(changed,wants)
        changed=copy.deepcopy(wants);changed[-1]['first']=True
        with self.assertRaises(ValueError):verify_observations(changed,wants)
    def test_changed_identity_time_and_consumption(self):
        _,_,rows=case_commands(self.v,self.v['cases'][0])
        for field,value in [('id','different'),('at',1),('kind','close')]:
            changed=copy.deepcopy(rows);changed[1][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):verify_rows(HEADER+b''.join(json.dumps(r).encode()+b'\n' for r in changed),rows)
        changed=copy.deepcopy(rows);changed[-1]['result_hex']=''
        with self.assertRaises(ValueError):verify_rows(HEADER+b''.join(json.dumps(r).encode()+b'\n' for r in changed),rows)
    def test_recovery_never_redelivers(self):
        for terminal in (False,True):
            write,read=recovery(self.v,terminal)
            self.assertFalse(read[1][1]['ok'])
            if terminal:
                self.assertEqual(write[2],read[2]);self.assertTrue(all(not x['first'] and not x['output_hex'] for x in read[1]))
            else:self.assertEqual(sum(x['first'] for x in read[1]),1)

if __name__=='__main__':unittest.main()
