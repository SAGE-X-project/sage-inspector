"""Offline evidence mutations; no live exploit or host bypass inputs."""
import copy
import json
import subprocess
import unittest
from test_guard_results010 import ROOT, expected, scenarios, state, validate_observations, validate_storage
from test_guard_reservations010 import HEADER


class ResultEvidence(unittest.TestCase):
    def setUp(self):
        self.suite=json.loads((ROOT/'vectors/0.10.0/guard-records.json').read_bytes())['cases']
        self.f=next(c['input'] for c in self.suite if c['id']=='intent-valid')
        self.envelope=bytes.fromhex(self.f['envelope_hex'])

    def test_missing_or_extra_responses(self):
        with self.assertRaises(ValueError):validate_observations([], [expected()], self.envelope)
        with self.assertRaises(ValueError):validate_observations([expected()[0]], [], self.envelope)

    def test_counters_and_false_publication(self):
        want=expected(ok=False, signs=1)
        for field,value in [('signs',2),('ok',True),('result_hex','00'),('committed',True)]:
            row=dict(want[0]);row[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):validate_observations([row],[want],self.envelope)

    def test_missing_terminal_bytes_and_extra_transition(self):
        i=json.loads(self.envelope)['intent'];row={k:i[k] for k in ('issuer','recipient','call_id','nonce','expires')}
        row.update(intent_hex=self.envelope.hex(),result_hex='',state='COMPLETED')
        raw=HEADER+json.dumps(row).encode()+b'\n'
        with self.assertRaises(ValueError):validate_storage(raw,self.envelope,[state('COMPLETED','completed')])
        with self.assertRaises(ValueError):validate_storage(raw,self.envelope,[])

    def test_expected_scenarios_cover_terminal_denials(self):
        self.assertEqual({c[0] for c in scenarios(self.f)}, {'pending-once','completed','rejected','rejection-conflict','signer-recovery','revoked','expired','accepted-late'})

    def test_independent_signature_audit(self):
        f=next(c['input'] for c in self.suite if c['id']=='result-completed-valid')
        raw=bytes.fromhex(f['envelope_hex']);result=json.loads(raw)['result']
        intent=f['intent_envelope']
        if not isinstance(intent,str):intent=json.dumps(intent,sort_keys=True,separators=(',',':'),ensure_ascii=False)
        case=dict(envelope_hex=raw.hex(),intent_hex=intent.encode().hex(),status=result['status'],output=result['output'],created=result['created'])
        def check(c):
            return subprocess.run(['node',str(ROOT/'scripts/check_guard_results010.js')],input=json.dumps(dict(public_key_hex=f['public_key_hex'],cases=[c])),text=True,capture_output=True,timeout=10).returncode
        self.assertEqual(check(case),0)
        for key,value in [('status','unknown'),('created',result['created']+1),('output',{'other':True}),('intent_hex',self.envelope.hex())]:
            changed=copy.deepcopy(case);changed[key]=value
            if changed==case:continue
            with self.subTest(key=key):self.assertNotEqual(check(changed),0)
        e=json.loads(raw);e['proof']='A'*86
        changed=dict(case,envelope_hex=json.dumps(e,sort_keys=True,separators=(',',':')).encode().hex())
        self.assertNotEqual(check(changed),0)

if __name__=='__main__':unittest.main()
