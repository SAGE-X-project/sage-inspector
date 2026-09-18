"""Offline mutations of reservation evidence, never executable exploit inputs."""
import copy
import json
import unittest
from test_guard_reservations010 import ROOT, HEADER, validate_journal, validate_reply


class ReservationEvidence(unittest.TestCase):
    def setUp(self):
        cases=json.loads((ROOT/'vectors/0.10.0/guard-records.json').read_bytes())['cases']
        self.envelope=bytes.fromhex(next(c['input']['envelope_hex'] for c in cases if c['id']=='intent-valid'))
        i=json.loads(self.envelope)['intent']
        self.row={k:i[k] for k in ('issuer','recipient','call_id','nonce','expires')}
        self.row.update(intent_hex=self.envelope.hex(),state='RESERVED',result_hex='')

    def journal(self, rows):
        return HEADER+b''.join(json.dumps(r).encode()+b'\n' for r in rows)

    def test_exact_projection(self):
        validate_journal(self.journal([self.row]),self.envelope,['RESERVED'])
        for key,value in [('issuer','other'),('nonce','other'),('intent_hex','7b7d'),('state','EXECUTING'),('result_hex','7b7d')]:
            row=copy.deepcopy(self.row);row[key]=value
            with self.assertRaises(ValueError):validate_journal(self.journal([row]),self.envelope,['RESERVED'])

    def test_duplicate_writes_and_false_success(self):
        with self.assertRaises(ValueError):validate_journal(self.journal([self.row,self.row]),self.envelope,['RESERVED'])
        with self.assertRaises(ValueError):validate_reply([dict(ok=True,created=True)],[dict(ok=True,created=False)])

    def test_unknown_cannot_be_promoted(self):
        row=dict(self.row,state='UNKNOWN')
        validate_journal(self.journal([self.row,row]),self.envelope,['RESERVED','UNKNOWN'])
        with self.assertRaises(ValueError):validate_journal(self.journal([self.row,row]),self.envelope,['RESERVED','COMPLETED'])


if __name__=='__main__':unittest.main()
