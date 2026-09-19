"""Reject incorrect effects and durable-state evidence in controlled Source runs."""
import json
import unittest
from test_guard_registry010 import ROOT,MODES,expected,validate
from test_guard_reservations010 import HEADER
class Reports(unittest.TestCase):
    def setUp(self):
        self.f=next(c['input'] for c in json.loads((ROOT/'vectors/0.10.0/guard-records.json').read_bytes())['cases'] if c['id']=='intent-valid')
        self.envelope=self.f['envelope_hex'];self.intent=json.loads(bytes.fromhex(self.envelope))['intent']
    def journal(self,mode):
        states=['RESERVED','EXECUTING']+([] if mode in ('valid','boundary') else ['UNKNOWN'])
        rows=[]
        for state in states:
            row={k:self.intent[k] for k in ('issuer','recipient','call_id','nonce','expires')}
            row.update(state=state,intent_hex=self.envelope,result_hex='');rows.append(json.dumps(row).encode())
        return HEADER+b'\n'.join(rows)+b'\n'
    def test_expected_observations(self):
        for mode in MODES:validate(mode,expected(mode),self.journal(mode),self.envelope)
    def test_reject_effect_and_missing_fresh_read(self):
        for field,value in [('ok',True),('committed',True),('effects',1),('reads',1),('ok',0),('effects',False)]:
            bad=expected('revoked');bad[field]=value
            with self.assertRaises(ValueError):validate('revoked',bad,self.journal('revoked'),self.envelope)
    def test_reject_storage_changes(self):
        for raw in [self.journal('valid'),self.journal('revoked').replace(b'UNKNOWN',b'COMPLETED'),self.journal('revoked')[:-1]]:
            with self.assertRaises(ValueError):validate('revoked',expected('revoked'),raw,self.envelope)
    def test_reject_wrong_intent_and_unknown_scenario(self):
        with self.assertRaises(ValueError):validate('valid',expected('valid'),self.journal('valid'),self.envelope+'20')
        with self.assertRaises(ValueError):expected('unknown')
if __name__=='__main__':unittest.main()
