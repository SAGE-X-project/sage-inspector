"""Offline controls for protected flow evidence; no attack traffic generation."""
import copy,json,unittest
from test_guard_session010 import ROOT,check_dispatch,check_effect
from test_guard_dispatch010 import expected_effect
from test_guard_client010 import verify_rows,event,HEADER
class Reports(unittest.TestCase):
    def setUp(self):
        v=json.loads((ROOT/'vectors/0.10.0/guard-rpc.json').read_bytes());self.intent=bytes.fromhex(v['input']['envelope_hex'])
        self.row=dict(ok=True,created=True,committed=True,state='EXECUTING',effects=[expected_effect(self.intent,'old')])
    def test_first_and_reuse(self):
        check_dispatch(self.row,self.intent,True)
        check_dispatch(dict(self.row,created=False,committed=False,state='COMPLETED'),self.intent,False)
    def test_missing_or_repeated_effect(self):
        for effects in ([],self.row['effects']*2):
            with self.assertRaises(ValueError):check_effect(dict(self.row,effects=effects),self.intent)
    def test_changed_arguments(self):
        row=copy.deepcopy(self.row);row['effects'][0]['arguments_hex']='00'
        with self.assertRaises(ValueError):check_effect(row,self.intent)
    def test_false_dispatch_claim(self):
        for key,value in [('ok',False),('created',False),('committed',False),('state','COMPLETED')]:
            with self.assertRaises(ValueError):check_dispatch(dict(self.row,**{key:value}),self.intent,True)
    def test_missing_terminal_journal(self):
        events=[event('open',intent_hex=self.intent.hex()),event('terminal','rpc',result_hex='fixture')]
        raw=HEADER+b''.join((json.dumps(e)+'\n').encode() for e in events)
        verify_rows(raw,events)
        with self.assertRaises(ValueError):verify_rows(HEADER+(json.dumps(events[0])+'\n').encode(),events)
if __name__=='__main__':unittest.main()
