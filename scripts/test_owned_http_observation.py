"""Synthetic checker controls. These mocks never count as native observations."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import owned_http_observation as o


def output(case, fixture):
    expected = case['expected']; target = 'https://127.0.0.1:32123/sage%2Fa?client=%2f'
    card = {'name':'inspection fixture','description':'','version':'1','supportedInterfaces':[{'url':target,'protocolBinding':'https://sage-x-project.github.io/sage-spec/a2a/0.10.0/binding','protocolVersion':'1.0'}],'capabilities':{'streaming':False,'extensions':[{'uri':'https://sage-x-project.github.io/sage-spec/a2a/0.10.0/extension','required':True,'params':{'sageVersion':'0.10.0','did':o.SERVER,'recordVersion':'17','issued':o.EPOCH,'expires':o.EPOCH+5}}]},'defaultInputModes':['application/json'],'defaultOutputModes':['application/json'],'skills':[{'id':'inspection','name':'inspection','description':'','tags':['inspection']}]}
    enc=lambda raw:base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
    card['signatures']=[{'protected':enc(o.canonical({'alg':'Ed25519','kid':o.SERVER+'#sign','typ':'sage-a2a-card+jws'})),'signature':enc(bytes(64))}]
    # Zero signature is a framing-only mock; actual crypto is checked remotely.
    n=expected['client_calls']; outcome=expected['outcome']
    replies=[fixture['reply_hex']]*n if outcome=='success' else ([o.canonical({'jsonrpc':'2.0','id':'inspection','error':{'code':-32004,'message':'Unsupported operation'}}).hex()] if outcome=='a2a-error' else [''])
    mode=case['input']['mode'];stamp=o.EPOCH+6 if mode.startswith('expired-') else o.EPOCH
    records=[{'did':who,'controller':'inspector-owned-operator','version':'17','signing_hex':fixture['public_keys'][key],'kem_hex':fixture['public_keys']['kem'] if key=='server' else '', 'service':target,'time':stamp} for who,key in ((o.CALLER,'caller'),(o.SERVER,'server'))]
    return {'target':target,'owner_type':'*a2abinding.HTTPTransportOwner','ingress_type':'*a2abinding.HTTPIngress','card_hex':o.canonical(card).hex(),**{k:expected[k] for k in ('client_calls','tls_handshakes','handler_calls','accepted_requests','accepted_responses','handler_payloads_hex')},'replies_hex':replies,'errors':['authentication failed'] if outcome=='refused' else ['']*n,'setup_reservations':[1,1],'source_reads':2,'source_observations':2,'records':records}


def rows():
    fixture,cases=o.fixtures()
    return fixture,cases,[{'id':c['id'],'input_sha256':c['input_sha256'],'actual':output(c,fixture)} for c in cases.values()]


class OwnedHTTPCheckerTests(unittest.TestCase):
    def test_all_groups_are_partial_and_old_subjects_not_merged(self):
        fixture,cases,observations=rows()
        self.assertEqual(len(cases),22)
        report=o.assess(observations)
        self.assertEqual(report['status_counts'],{'PARTIAL':4,'NOT_RUN':579})
        self.assertFalse(report['historical_results_merged'])
        self.assertEqual(report['scope']['automatic_owner_retirement'],'NOT_OBSERVED_BY_THIS_OBSERVER')
        self.assertEqual(o.assess([])['status_counts'],{'NOT_RUN':583})
        observations.pop()
        self.assertIn('NOT_RUN',o.assess(observations)['status_counts'])
        bad=copy.deepcopy(observations);bad[0]['actual']['accepted_responses']=0
        self.assertGreater(o.assess(bad)['status_counts']['FAIL'],0)

    def test_input_and_subject_identity_refusals(self):
        _,_,observations=rows()
        variants=[None,observations*2,[observations[0],observations[0]]]
        for key,value in [('id','unknown'),('id',[]),('input_sha256','0'*64),('extra','PASS')]:
            row=copy.deepcopy(observations[0]);row[key]=value;variants.append([row])
        for value in variants:
            with self.subTest(value=str(value)[:70]),self.assertRaises(ValueError):o.assess(value)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/o.SUBJECT).parent.mkdir(parents=True)
            (root/o.SUBJECT).write_text('{}')
            with self.assertRaisesRegex(ValueError,'subject drift'):o.subject(root)
            (root/o.FIXTURE).parent.mkdir(parents=True)
            (root/o.FIXTURE).write_text('{}')
            with self.assertRaisesRegex(ValueError,'fixture drift'):o.fixtures(root)

    def test_actual_field_mutations_refuse_without_network(self):
        fixture,cases,observations=rows();case=cases['bare/success'];base=next(x['actual'] for x in observations if x['id']==case['id'])
        variants=[]
        for key,value in [('target',None),('target','https://127.0.0.1:99999/sage%2Fa?client=%2f'),('target','https://127.0.0.1:32123/sage%2fa?client=%2f'),('owner_type','ownerFunc'),('ingress_type','http.Handler'),('client_calls',True),('tls_handshakes',0),('handler_calls',0),('accepted_requests',0),('accepted_responses',True),('source_reads',0),('source_observations',False),('setup_reservations',[True,1]),('handler_payloads_hex',[]),('replies_hex',['00']),('errors',['bad']),('card_hex','00'),('card_hex',''),('records',[]),('extra',1)]:
            bad=copy.deepcopy(base);bad[key]=value;variants.append(bad)
        for field,value in [('did','wrong'),('controller','wrong'),('version','18'),('signing_hex','00'),('kem_hex','00'),('service','wrong'),('time',True)]:
            bad=copy.deepcopy(base);bad['records'][0][field]=value;variants.append(bad)
        for bad in variants:
            with self.subTest(field=str(bad)[:60]):self.assertFalse(o.matches(bad,case,fixture))
        expired=cases['bare/expired-after-setup'];bad=output(expired,fixture)
        for record in bad['records']:record['time']=o.EPOCH
        self.assertFalse(o.matches(bad,expired,fixture))
        source=cases['bare/source-after-setup'];bad=output(source,fixture);bad['source_reads']=1;bad['source_observations']=1
        self.assertFalse(o.matches(bad,source,fixture))
        late=cases['bare/cancel-during-handler'];bad=output(late,fixture);bad['handler_calls']=0
        self.assertFalse(o.matches(bad,late,fixture))
        unsupported=cases['bare/unsupported'];bad=output(unsupported,fixture);bad['replies_hex']=['00']
        self.assertFalse(o.matches(bad,unsupported,fixture))

    def test_card_and_base64_controls(self):
        fixture,cases,observations=rows();actual=observations[0]['actual']
        for raw in ('','a=','!', 'AB'):
            with self.assertRaises((ValueError,TypeError)):o.decode64(raw)
        card=json.loads(bytes.fromhex(actual['card_hex']))
        for name in ('signature','header','facts','missing'):
            bad=copy.deepcopy(card)
            if name=='signature':bad['signatures'][0]['signature']='AA'
            elif name=='header':bad['signatures'][0]['protected']=base64.urlsafe_b64encode(b'{}').decode().rstrip('=')
            elif name=='facts':bad['version']='2'
            else:del bad['signatures']
            with self.assertRaises(ValueError):o.card_facts(o.canonical(bad).hex(),actual['target'])

    def test_module_and_compiler_provenance_are_separate(self):
        expected=o.subject()['modules']; info={'GoVersion':'go1.26.8','Path':'github.com/sage-x-project/sage-inspector/adapters/a2a-owned-http','Deps':[{'Path':p,'Version':v['Version'],'Sum':v['Sum']} for p,v in expected.items()]}
        o.compiled_modules(info,expected)
        for mode in ('compiler','path','missing','version','sum','replace','empty-replace','duplicate'):
            bad=copy.deepcopy(info)
            if mode=='compiler':bad['GoVersion']='go1.26.9'
            elif mode=='path':bad['Path']='wrong'
            elif mode=='missing':bad['Deps'].pop()
            elif mode=='replace':bad['Deps'][0]['Replace']={'Path':'local'}
            elif mode=='empty-replace':bad['Deps'][0]['Replace']={}
            elif mode=='duplicate':bad['Deps'].append(bad['Deps'][0])
            else:bad['Deps'][0][mode.title()]='wrong'
            with self.subTest(mode=mode),self.assertRaises(ValueError):o.compiled_modules(bad,expected)
        responses=[SimpleNamespace(stdout=json.dumps({'Path':p,**v}).encode()) for p,v in expected.items()]+[SimpleNamespace(stdout=b'all modules verified\n')]
        with patch.object(o,'execute',side_effect=responses):self.assertEqual(len(o.module_info('go',Path('.'),{},expected)),4)
        for value in ({'Path':'wrong'}, {'Path':next(iter(expected)),**next(iter(expected.values())),'Replace':{'Path':'local'}}):
            with patch.object(o,'execute',return_value=SimpleNamespace(stdout=json.dumps(value).encode())),self.assertRaises(ValueError):o.module_info('go',Path('.'),{},expected)
        with patch.object(o,'execute',return_value=SimpleNamespace(stdout=b'{"GoFiles":["main.go"]}')),self.assertRaises(ValueError):o.compiler_inputs('go',Path('.'),{})
        directory=o.ROOT/o.ADAPTER
        with patch.object(o,'execute',return_value=SimpleNamespace(stdout=b'{"GoFiles":["fixture.go","main.go"]}')):self.assertEqual(len(o.compiler_inputs('go',directory,{})),4)

    def test_native_orchestration_mock_is_not_runtime_evidence(self):
        fixture,cases,observations=rows();expected=o.subject()['modules']
        info={'GoVersion':'go1.26.8','Path':'github.com/sage-x-project/sage-inspector/adapters/a2a-owned-http','Deps':[{'Path':p,'Version':v['Version'],'Sum':v['Sum']} for p,v in expected.items()]}
        def command(cmd,*args,**kwargs):
            if cmd[1:] == ['version']: return SimpleNamespace(stdout=b'go version go1.26.8 linux/amd64\n')
            if cmd[1]=='build':Path(cmd[cmd.index('-o')+1]).write_bytes(b'mocked binary');return SimpleNamespace(stdout=b'')
            if cmd[1:4]==['version','-m','-json']:return SimpleNamespace(stdout=json.dumps(info).encode())
            if cmd[0]=='git':return SimpleNamespace(stdout=b'1'*40+b'\n')
            raise AssertionError(cmd)
        def process(cmd,input,**kwargs):
            selector=json.loads(input);case=cases[selector['completion']+'/'+selector['mode']]
            return SimpleNamespace(stdout=json.dumps(output(case,fixture)).encode(),stderr=b'',returncode=0)
        with patch.object(o,'execute',side_effect=command),patch.object(o,'compiler_inputs',return_value={p:o.sha((o.ROOT/o.ADAPTER/p).read_bytes()) for p in ('main.go','fixture.go','go.mod','go.sum')}),patch.object(o,'module_info',return_value=[{'Path':p,**v} for p,v in expected.items()]),patch.object(o.subprocess,'run',side_effect=process):
            import io
            attempts=io.StringIO();report=o.run_native('go',attempts=attempts)
            self.assertEqual(report['execution']['process_count'],22)
            self.assertEqual(len(attempts.getvalue().splitlines()),22)
            self.assertEqual(report['status_counts'],{'PARTIAL':4,'NOT_RUN':579})
            from check_owned_http_evidence import verify
            with tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp)
                (directory/'owned-http-native.attempts.jsonl').write_text(attempts.getvalue())
                (directory/'owned-http-revision.txt').write_text('1'*40+'\n')
                (directory/'owned-http-native.json').write_text(json.dumps(report))
                verify(directory)
                altered=[json.loads(line) for line in attempts.getvalue().splitlines()]
                altered[0]['returncode']=False
                (directory/'owned-http-native.attempts.jsonl').write_text(''.join(json.dumps(t)+'\n' for t in altered))
                with self.assertRaises(ValueError):verify(directory)
                (directory/'owned-http-native.attempts.jsonl').write_text(attempts.getvalue())
                bad=copy.deepcopy(report);bad['execution']['process_count']=22.0
                (directory/'owned-http-native.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError):verify(directory)
                for field,value in [('status_counts',{'PASS':583}),('historical_results_merged',True),('cases',[]),('fixture_sha256','0'*64),('protocol_version','fake')]:
                    bad=copy.deepcopy(report);bad[field]=value
                    (directory/'owned-http-native.json').write_text(json.dumps(bad))
                    with self.assertRaises(ValueError):verify(directory)
                bad=copy.deepcopy(report);bad['cases'][0]['status']='PASS'
                (directory/'owned-http-native.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError):verify(directory)
                bad=copy.deepcopy(report);bad['execution']['raw_trace'][0]['stdout_sha256']='0'*64
                (directory/'owned-http-native.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError):verify(directory)
                for field,value in [('repository','other/repo'),('revision','2'*40)]:
                    bad=copy.deepcopy(report);bad['observer'][field]=value
                    (directory/'owned-http-native.json').write_text(json.dumps(bad))
                    with self.assertRaises(ValueError):verify(directory)
                bad=copy.deepcopy(report);bad['execution']['adapter_sha256']=''
                (directory/'owned-http-native.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError):verify(directory)
                bad=copy.deepcopy(report);trace=bad['execution']['raw_trace'][0]
                raw=json.loads(bytes.fromhex(trace['stdout_hex']));raw['client_calls']=True
                data=o.canonical(raw);trace['stdout_hex']=data.hex();trace['stdout_sha256']=o.sha(data)
                (directory/'owned-http-native.attempts.jsonl').write_text(''.join(json.dumps(t)+'\n' for t in bad['execution']['raw_trace']))
                (directory/'owned-http-native.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError):verify(directory)
            with patch.object(o.subprocess,'run',return_value=SimpleNamespace(stdout=b'',stderr=b'refused',returncode=1)),self.assertRaisesRegex(ValueError,'clean owned'):o.run_native('go')

    def test_cli_and_report_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'inventory.json'
            with patch.object(sys,'argv',['observe','--output',str(path)]):o.main()
            self.assertEqual(json.loads(path.read_bytes())['status_counts'],{'NOT_RUN':583})
            with patch.object(sys,'argv',['observe','--output',str(path)]),self.assertRaises(SystemExit):o.main()
            path=Path(tmp)/'native.json'
            report=o.assess(rows()[2])
            with patch.object(sys,'argv',['observe','--native','--output',str(path)]),patch.object(o,'run_native',return_value=report):o.main()
            path=Path(tmp)/'incomplete.json'
            with patch.object(sys,'argv',['observe','--native','--output',str(path)]),patch.object(o,'run_native',return_value=o.assess([])),self.assertRaises(SystemExit):o.main()
            path=Path(tmp)/'failed.json';report['status_counts']={'FAIL':1,'NOT_RUN':582}
            with patch.object(sys,'argv',['observe','--native','--output',str(path)]),patch.object(o,'run_native',return_value=report),self.assertRaises(SystemExit):o.main()
            self.assertEqual(json.loads(path.read_bytes())['status_counts']['FAIL'],1)

if __name__=='__main__':unittest.main()
