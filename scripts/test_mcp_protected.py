"""Local checker controls; modified observations never go to a network peer."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import mcp_protected_support as flow
from run_mcp_setup_interop import validate as setup

FIXTURE = Path(__file__).parent/'fixtures/mcp-protected.json'


class ProtectedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name,raw in json.loads(FIXTURE.read_text())['files'].items():
            (self.root/name).write_text(raw)
        frames = json.loads((self.root/'frames.json').read_text())
        self.requests = [bytes.fromhex(x) for x in frames['requests']]
        self.responses = [bytes.fromhex(x) for x in frames['responses']]
        self.setup = {'session_id':json.loads(self.requests[1])['session_id'],'independent_signatures':9}

    def check(self):
        return flow.validate(self.root,self.requests,self.responses,self.setup)

    def edit(self,name,change):
        p=self.root/name;original=p.read_text();value=json.loads(original)
        change(value);p.write_text(json.dumps(value))
        try:
            with self.assertRaises(ValueError):self.check()
        finally:p.write_text(original)

    def test_real_public_fixture_signatures_and_journals(self):
        result=setup(self.requests[:4],self.responses[:4])
        self.assertEqual(result['session_id'],self.setup['session_id'])
        observation=self.check()
        self.assertEqual(observation['effects'],1)
        self.assertEqual(observation['frames'],len(self.requests)+len(self.responses))
        self.assertEqual(observation['independent_signatures'],9+2*(len(self.requests)-4)+2)

    @patch.object(flow,'verify')
    def test_delivery_and_effect_disagreement(self,_):
        self.edit('server.json',lambda v:v.update(effects=2))
        self.edit('client.json',lambda v:v.update(first_terminal=False))
        self.edit('client.json',lambda v:v.update(output_hex='00'))
        self.edit('client.json',lambda v:v.update(repeat_denied=False))
        self.edit('client.json',lambda v:v.update(attempts=0))

    @patch.object(flow,'verify')
    def test_journal_transition_and_consumption_disagreement(self,_):
        for file,mode in [('server.journal','duplicate'),('server.journal','intent'),
                          ('server.journal','state'),('client.journal','duplicate'),
                          ('client.journal','consume'),('client.journal','result')]:
            path=self.root/file;original=path.read_text();lines=original.splitlines()
            records=[json.loads(x) for x in lines[1:]]
            if mode=='duplicate':records.append(records[-1])
            if mode=='intent':records[1]['intent_hex']='00'
            if mode=='state':records[1]['state']='UNKNOWN'
            if mode=='consume':records[2]['id']='unrelated'
            if mode=='result':records[-1]['result_hex']='00'
            path.write_text(lines[0]+'\n'+'\n'.join(json.dumps(x) for x in records)+'\n')
            try:
                with self.assertRaises(ValueError,msg=mode):self.check()
            finally:path.write_text(original)

    @patch.object(flow,'verify')
    def test_signed_wire_binding_disagreement(self,_):
        for key,value in [('session_id','other'),('request_hash','other'),('success',False),('did',flow.ALICE)]:
            original=self.responses[-1];v=json.loads(original);v[key]=value
            self.responses[-1]=flow.canonical(v)
            try:
                with self.assertRaises(ValueError,msg=key):self.check()
            finally:self.responses[-1]=original

    def test_real_signature_failure_is_not_accepted(self):
        original=self.responses[-1];v=json.loads(original);v['signature']=flow.encode(bytes(64))
        self.responses[-1]=flow.canonical(v)
        with self.assertRaises(AssertionError):self.check()


if __name__=='__main__':unittest.main()
