"""Local checker controls; modified observations never go to a network peer."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import mcp_protected_support as flow
import mcp_record_plaintext as plaintext
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
        self.setup = setup(self.requests[:4],self.responses[:4])

    def check(self):
        return flow.validate(self.root,self.requests,self.responses,self.setup)

    def edit(self,name,change):
        p=self.root/name;original=p.read_text();value=json.loads(original)
        change(value);p.write_text(json.dumps(value))
        try:
            with self.assertRaises(ValueError):self.check()
        finally:p.write_text(original)

    def test_real_public_fixture_signatures_and_journals(self):
        result=self.setup
        self.assertEqual(result['session_id'],json.loads(self.requests[1])['session_id'])
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

    def test_observation_types_are_not_coerced(self):
        for value in (True, 1.0): self.edit('server.json',lambda v:v.update(effects=value))
        for field in ('first_terminal','repeat_denied'):
            self.edit('client.json',lambda v:v.update({field:1}))
        self.edit('client.json',lambda v:v.update(attempts=float(v['attempts'])))

    def test_journal_integer_fields_are_not_coerced(self):
        for name,index,field,value in [('client.journal',1,'at',False),
                                       ('client.journal',2,'at',460000.0),
                                       ('client.journal',3,'at',0.0),
                                       ('client.journal',-1,'at',False),
                                       ('server.journal',1,'expires',760.0)]:
            p=self.root/name;raw=p.read_text();lines=raw.splitlines();row=json.loads(lines[index]);row[field]=value
            lines[index]=json.dumps(row);p.write_text('\n'.join(lines)+'\n')
            with self.assertRaises(ValueError):self.check()
            p.write_text(raw)

    @patch.object(flow,'verify')
    def test_result_time_must_be_integer(self,_):
        for name in ('server.journal','client.journal'):
            p=self.root/name;lines=p.read_text().splitlines();row=json.loads(lines[-1])
            envelope=json.loads(bytes.fromhex(row['result_hex']));envelope['result']['created']=float(envelope['result']['created'])
            row['result_hex']=flow.canonical(envelope).hex();lines[-1]=json.dumps(row)
            p.write_text('\n'.join(lines)+'\n')
        with self.assertRaisesRegex(ValueError,'signed result binding'):self.check()

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


class RecoveryTests(unittest.TestCase):
    setUp = ProtectedTests.setUp
    def prepare(self):
        for name in ('client.journal','server.journal'):
            (self.root/(name+'.before')).write_bytes((self.root/name).read_bytes())
        (self.root/'client.json').write_text(json.dumps(dict(role='client',state='READY',reopen_denied=True)))
        (self.root/'server.json').write_text(json.dumps(dict(role='server',state='READY',effects=0)))

    def recovered(self, requests=None):
        return flow.validate_recovery(self.root, self.requests[:4] if requests is None else requests,
                                      self.responses[:4], self.setup, 'client')

    def test_consumed_client_reopen(self):
        self.prepare()
        self.assertEqual(self.recovered()['protected_exchanges'],0)

    def test_reopen_observation_types(self):
        self.prepare()
        for name,key,value in [('server.json','effects',False),('server.json','effects',0.0),
                               ('client.json','reopen_denied',1)]:
            p=self.root/name;raw=p.read_text();row=json.loads(raw);row[key]=value;p.write_text(json.dumps(row))
            with self.assertRaises(ValueError):self.recovered()
            p.write_text(raw)

    def test_reopen_cannot_hide_extra_traffic(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError,'protected traffic'):
            self.recovered(self.requests)

    def test_reopen_requires_unchanged_journals(self):
        self.prepare()
        for name in ('client.journal','server.journal'):
            p=self.root/name;raw=p.read_bytes();p.write_bytes(raw+b'\n')
            with self.assertRaisesRegex(ValueError,'journal changed'):
                self.recovered()
            p.write_bytes(raw)

    def test_reopen_requires_no_effect_and_explicit_denial(self):
        self.prepare()
        for name,field,value in [('server.json','effects',1),('client.json','reopen_denied',False)]:
            p=self.root/name;raw=p.read_text();v=json.loads(raw);v[field]=value;p.write_text(json.dumps(v))
            with self.assertRaises(ValueError):self.recovered()
            p.write_text(raw)


class ServerRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for name,raw in json.loads(FIXTURE.with_name('mcp-recovery.json').read_text())['files'].items():
            (self.root/name).write_text(raw)
        frames=json.loads((self.root/'frames.json').read_text())
        self.requests=[bytes.fromhex(x) for x in frames['requests']]
        self.responses=[bytes.fromhex(x) for x in frames['responses']]
        self.setup=setup(self.requests[:4],self.responses[:4])

    def check(self):
        return flow.validate_recovery(self.root,self.requests,self.responses,self.setup,'server')

    def test_cached_result_signatures_and_no_new_execution(self):
        setup(self.requests[:4],self.responses[:4])
        result=self.check()
        self.assertEqual(result['effects'],0)
        self.assertEqual(result['protected_exchanges'],1)
        self.assertEqual(result['independent_signatures'],13)

    def test_server_recovery_rejects_new_effect(self):
        p=self.root/'server.json';v=json.loads(p.read_text());v['effects']=1;p.write_text(json.dumps(v))
        with self.assertRaises(ValueError):self.check()

    def test_server_recovery_rejects_rewritten_ledger(self):
        p=self.root/'server.journal';p.write_bytes(p.read_bytes()+b'\n')
        with self.assertRaisesRegex(ValueError,'journal changed'):self.check()

    def test_server_recovery_rejects_changed_delivered_result(self):
        p=self.root/'client.journal';lines=p.read_text().splitlines();v=json.loads(lines[-1]);v['result_hex']='00'
        lines[-1]=json.dumps(v);p.write_text('\n'.join(lines)+'\n')
        with self.assertRaisesRegex(ValueError,'terminal bytes differ'):self.check()


class IndependentRecordDecryptionTests(unittest.TestCase):
    VECTOR=dict(direction=0,
        seed_hex='a670cc6a4cf4eed950a26f2e85a185457e283ba617fd87da485625d96a2a61a6',
        th_hex='a4dcfbf2cfe2b3ffd09acd65fbb78c675612b93c93b512a11b9b064786ee5488',
        wire_hex='00000000000000000000000000000000000000000882116e879457582f3d127ea08eba98185f3bf0eef94b5ad246e724a9ea9cc763de56b152',
        aad_hex='7b7d')

    def run_checker(self,vector):
        return subprocess.run(['node',str(Path(__file__).parent/'check_mcp_record_plaintext.js')],
                              input=json.dumps([vector]),text=True,capture_output=True,timeout=10)

    def test_public_record_vector(self):
        result=self.run_checker(self.VECTOR)
        self.assertEqual(result.returncode,0,result.stderr)
        opened=json.loads(result.stdout)[0]
        self.assertEqual(bytes.fromhex(opened['plaintext_hex']),b'public session record')

    def test_changed_ciphertext_is_rejected_locally(self):
        changed=dict(self.VECTOR);wire=bytearray.fromhex(changed['wire_hex']);wire[-1]^=1
        changed['wire_hex']=wire.hex();result=self.run_checker(changed)
        self.assertNotEqual(result.returncode,0)


class DecryptedMessageBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        fixture=json.loads(FIXTURE.read_text())['files']
        for name in ('intent.json','server.journal'):
            (self.root/name).write_text(fixture[name])
        intent=json.loads(fixture['intent.json'])
        rows=[json.loads(v) for v in fixture['server.journal'].splitlines()[1:]]
        completed=json.loads(bytes.fromhex(rows[-1]['result_hex']))
        call='00000000-0000-4000-8000-000000000091'
        requests=[
            {'jsonrpc':'2.0','id':'00000000-0000-4000-8000-000000000081','method':'initialize'},
            {'jsonrpc':'2.0','method':'notifications/initialized'},
            {'jsonrpc':'2.0','id':'00000000-0000-4000-8000-000000000082','method':'tools/list'},
            {'jsonrpc':'2.0','id':call,'method':'tools/call','params':{'name':'sage_secure_call','arguments':{'envelope':intent}}},
        ]
        wrapped={'content':[{'type':'text','text':flow.canonical(completed).decode()}],
                 'isError':False,'structuredContent':completed}
        responses=[
            {'jsonrpc':'2.0','id':requests[0]['id'],'result':{'protocolVersion':'2025-06-18'}},
            {},
            {'jsonrpc':'2.0','id':requests[2]['id'],'result':{'tools':[]}},
            {'jsonrpc':'2.0','id':call,'result':wrapped},
        ]
        self.messages=([flow.canonical(v) for v in requests],[flow.canonical(v) for v in responses])

    def check(self):
        with patch.object(plaintext,'decrypt',return_value=self.messages):
            return plaintext.validate_plaintext(self.root,[],[],{})

    def test_intent_and_terminal_journal_binding(self):
        result=self.check()
        self.assertEqual(result['decrypted_protected_exchanges'],1)
        self.assertEqual(result['decrypted_result_signatures'],1)

    def test_changed_decrypted_intent_is_rejected(self):
        original=self.messages[0][-1];value=json.loads(original)
        value['params']['arguments']['envelope']['intent']['tool']='changed'
        self.messages[0][-1]=flow.canonical(value)
        try:
            with self.assertRaisesRegex(ValueError,'intent differs'):self.check()
        finally:self.messages[0][-1]=original


if __name__=='__main__':unittest.main()
