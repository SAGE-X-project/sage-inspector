"""Offline evidence mutations for dispatch bindings, never live exploit inputs."""
import copy
import json
import unittest
from test_guard_dispatch010 import ROOT, scenarios, expected_effect, observation
from test_guard_reservations010 import validate_reply, validate_journal, HEADER


class DispatchEvidence(unittest.TestCase):
    def setUp(self):
        suite=json.loads((ROOT/'vectors/0.10.0/guard-records.json').read_bytes())
        self.f=next(c['input'] for c in suite['cases'] if c['id']=='intent-valid')
        self.envelope=bytes.fromhex(self.f['envelope_hex'])

    def test_exact_component_arguments_and_proof(self):
        expected=observation(effects=[expected_effect(self.envelope,'old')])
        validate_reply(expected,expected)
        for key in ('instance','arguments_hex','envelope_hex','manifest_digest','intent_digest','tool'):
            changed=copy.deepcopy(expected);changed['effects'][0][key]='different'
            with self.assertRaises(ValueError):validate_reply(changed,expected)

    def test_duplicate_and_retirement_cannot_commit(self):
        for name,_,expected,_ in scenarios(self.f):
            changed=copy.deepcopy(expected)
            changed[-1]['committed']=not changed[-1]['committed']
            with self.subTest(name=name),self.assertRaises(ValueError):validate_reply(changed,expected)

    def test_restart_never_claims_completion(self):
        i=json.loads(self.envelope)['intent']
        row={k:i[k] for k in ('issuer','recipient','call_id','nonce','expires')}
        row.update(intent_hex=self.envelope.hex(),result_hex='')
        states=['RESERVED','EXECUTING','UNKNOWN']
        raw=HEADER+b''.join(json.dumps(dict(row,state=s)).encode()+b'\n' for s in states)
        validate_journal(raw,self.envelope,states)
        with self.assertRaises(ValueError):validate_journal(raw,self.envelope,['RESERVED','EXECUTING','COMPLETED'])


if __name__=='__main__':unittest.main()
