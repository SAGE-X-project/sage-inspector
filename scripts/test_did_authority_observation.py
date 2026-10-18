"""Synthetic inspector controls never count as actual Verifier/native evidence."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import did_authority_observation as o


def unit_rows():
    fixture,cases = o.fixtures()
    rows = []
    for name,c in cases.items():
        interfaces = [{'URL':fixture['target'],'Tenant':''}] if c['expected']['accepted'] else []
        records = [] if c['source_mode'] == 'unavailable' else [o.source_record(d,c['source_mode'],fixture) for d in c['expected']['source_dids']]
        actual = {'id':name,'input_card_hex':c['input_card_hex'],'signing_public_hex':c['signing_public_hex'],'source_mode':c['source_mode'],'configured_expected_peer':c['expected_peer'],'std_signature_valid':True,'result':copy.deepcopy(c['expected']),'source_records':records,'eligible_interfaces':interfaces}
        rows.append({'id':name,'input_sha256':c['input_sha256'],'actual':actual})
    return rows


def native_rows():
    own,own_cases = o.fixtures()
    target='https://127.0.0.1:32123/sage%2Fa?client=%2f'
    records=[{'did':d,'controller':'inspector-owned-operator','version':'17','signing_hex':own['public_keys'][k],'kem_hex':own['public_keys']['kem'] if d==o.SERVER else '', 'service':target,'time':o.EPOCH} for d,k in [(o.CALLER,'C'),(o.SERVER,'A')]]
    actual={'target':target,'owner_type':'*a2abinding.HTTPTransportOwner','ingress_type':'*a2abinding.HTTPIngress','client_calls':1,'tls_handshakes':1,'handler_calls':1,'accepted_requests':1,'accepted_responses':1,'handler_payloads_hex':[b' {"jsonrpc":"2.0","id":"inspection","method":"GetTask","params":{"id":"owned-task"}} '.hex()],'replies_hex':[b'{"jsonrpc":"2.0","id":"inspection","result":{"ok":true}}'.hex()],'errors':[''],'setup_reservations':[1,1],'source_reads':2,'source_observations':2,'records':records}
    card = o.load(bytes.fromhex(own_cases['matching-document-calibration']['input_card_hex']))
    card['supportedInterfaces'][0]['url'] = actual['target']
    # The retained fixture signature here is not a valid signature for changed
    # URL bytes. This is strictly a Python framing/fact checker mock.
    actual['card_hex'] = o.canonical(card).hex()
    actual.update(verified_card_hex=actual['card_hex'],verified_did=o.SERVER,verified_version='17',eligible_interfaces=[{'URL':actual['target'],'Tenant':''}])
    return [{'id':name,'input_sha256':o.sha(o.canonical({'completion':name})),'actual':copy.deepcopy(actual)} for name in ('bare','http')]


def events(rows=None):
    rows = unit_rows() if rows is None else rows
    package = 'github.com/sage-x-project/sage-inspector/adapters/a2a-did-authority'
    result = [{'Action':'start','Package':package}]
    for row in rows:
        test = 'TestCardAuthority/'+row['id']
        result += [{'Action':'run','Package':package,'Test':test},{'Action':'output','Package':package,'Test':test,'Output':'    main_test.go:330: AUTHORITY_OBSERVATION '+json.dumps(row['actual'])+'\n'},{'Action':'pass','Package':package,'Test':test}]
    result.append({'Action':'pass','Package':package})
    return result


def encode(value):return b''.join(o.canonical(e)+b'\n' for e in value)


class AuthorityCheckerTests(unittest.TestCase):
    def test_complete_and_partial_are_separate_from_old_results(self):
        report=o.assess(native_rows(),unit_rows())
        self.assertEqual(report['status_counts'],{'PARTIAL':2,'NOT_RUN':581})
        self.assertFalse(report['historical_results_merged'])
        self.assertEqual(o.assess(native_rows(),[])['status_counts'],{'NOT_RUN':583})
        self.assertEqual(o.assess([],unit_rows())['status_counts'],{'NOT_RUN':583})
        self.assertEqual(len(o.parse_units(encode(events()))),13)
        bad=unit_rows();bad[0]['actual']['result']['accepted']=False
        self.assertEqual(o.assess(native_rows(),bad)['status_counts']['FAIL'],2)
        fixture,cases=o.fixtures()
        self.assertEqual(len(cases),13)
        self.assertEqual(len({c['input_card_hex'] for c in cases.values()}),9)
        self.assertNotEqual(cases['matching-document-calibration']['input_sha256'],cases['missing-signing-key']['input_sha256'])

    def test_closed_fixture_and_input_identity(self):
        for native,units in [(None,[]),([],None),(native_rows()*2,[]),([] ,unit_rows()*2),([native_rows()[0]]*2,[]),([],[unit_rows()[0]]*2)]:
            with self.assertRaises((ValueError,TypeError)):o.assess(native,units)
        for collection in ('native','units'):
            for field,value in [('id','unknown'),('id',[]),('input_sha256','0'*64),('extra',True)]:
                rows=native_rows() if collection=='native' else unit_rows();rows[0][field]=value
                with self.assertRaises((ValueError,TypeError)):o.assess(rows,[]) if collection=='native' else o.assess([],rows)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for rel,func in [(o.SUBJECT,o.subject),(o.FIXTURE,o.fixtures)]:
                path=root/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('{}')
                with self.assertRaises(ValueError):func(root)

    def test_authority_effective_record_and_interfaces(self):
        fixture,cases=o.fixtures();base=unit_rows()[2]['actual'];case=cases[base['id']]
        for key,value in [('std_signature_valid',1),('configured_expected_peer',o.CALLER),('source_mode','unavailable'),('input_card_hex','00'),('eligible_interfaces',[]),('source_records',[]),('result',{}),('extra','PASS')]:
            bad=copy.deepcopy(base);bad[key]=value
            with self.subTest(key=key):self.assertFalse(o.unit_matches(bad,case,fixture))
        for field,value in [('did',o.CALLER),('controller','peer-controlled'),('version','18'),('state','deactivated'),('keys',[]),('service','https://wrong.invalid')]:
            bad=copy.deepcopy(base);bad['source_records'][0][field]=value
            self.assertFalse(o.unit_matches(bad,case,fixture))
        for name in ('missing-signing-key','revoked-signing-key'):
            row=next(r for r in unit_rows() if r['id']==name)
            self.assertTrue(o.unit_matches(row['actual'],cases[name],fixture))
            row['actual']['source_records'][0]['keys']=[k for k in row['actual']['source_records'][0]['keys'] if k['name']!='other']
            self.assertFalse(o.unit_matches(row['actual'],cases[name],fixture))

    def test_independent_record_contract_spelling(self):
        fixture,_=o.fixtures()
        actual=o.source_record(o.SERVER,'revoked-sign',fixture)
        self.assertEqual([(k['name'],k['alg'],k['state']) for k in actual['keys']], [('kem','x25519','accepted'),('other','ed25519','accepted'),('sign','ed25519','revoked')])
        self.assertEqual(actual['state'],'active')
        self.assertEqual(actual['keys'][1]['material_hex'],'bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a6')

    def test_attributed_unit_log_refuses_missing_duplicate_or_failure(self):
        variants=[]
        good=events()
        variants += [[],good[:-1],good+good,good+[{'Action':'fail','Package':good[0]['Package'],'Test':'AnotherTest'}]]
        for field,value in [('Package','wrong'),('Test','TestOther/baseline'),('Action','pass')]:
            bad=copy.deepcopy(good);bad[2][field]=value;variants.append(bad)
        bad=copy.deepcopy(good);bad[2]['Output']=bad[2]['Output'].replace('"std_signature_valid": true','"std_signature_valid": 1');variants.append(bad)
        bad=copy.deepcopy(good);bad[2]['Output']=bad[2]['Output'].replace('"accepted": true','"accepted": 1');variants.append(bad)
        bad=copy.deepcopy(good);bad[2]['Output']=bad[2]['Output'].replace('"id": "baseline"','"id": "unknown"',1);variants.append(bad)
        bad=copy.deepcopy(good);bad[3]['Test']='TestCardAuthority/unknown';variants.append(bad)
        bad=copy.deepcopy(good);bad.insert(3,copy.deepcopy(bad[2]));variants.append(bad)
        for value in variants:
            with self.subTest(kind=str(value)[:60]),self.assertRaises((ValueError,TypeError,KeyError)):o.parse_units(encode(value))
        with self.assertRaises(ValueError):o.parse_units('not bytes')

    def test_benign_native_fact_mutations(self):
        fixture,_=o.fixtures();base=native_rows()[0]['actual']
        for key,value in [('target',None),('target','https://127.0.0.1:99999/sage%2Fa?client=%2f'),('target','https://evil.invalid'),('owner_type','mock'),('ingress_type','mock'),('handler_calls',True),('source_reads',0),('source_observations',False),('setup_reservations',[True,1]),('errors',['error']),('replies_hex',['']),('handler_payloads_hex',[]),('verified_card_hex',''),('verified_did',o.CALLER),('verified_version','18'),('eligible_interfaces',[]),('card_hex',''),('records',[]),('extra',1)]:
            bad=copy.deepcopy(base);bad[key]=value
            with self.subTest(key=key):self.assertFalse(o.native_matches(bad,fixture))
        for mode in ('signature','claims','record'):
            bad=copy.deepcopy(base)
            if mode=='record':bad['records'][0]['time']=True
            else:
                card=o.load(bytes.fromhex(bad['card_hex']))
                if mode=='signature':card['signatures'][0]['signature']='AA'
                else:card['version']='2'
                bad['card_hex']=o.canonical(card).hex();bad['verified_card_hex']=bad['card_hex']
            self.assertFalse(o.native_matches(bad,fixture))

    def test_compiled_provenance_and_closed_build_inputs(self):
        expected=o.subject()['modules'];info={'GoVersion':'go1.26.8','Path':'github.com/sage-x-project/sage-inspector/adapters/a2a-did-authority','Deps':[{'Path':p,'Version':v['Version'],'Sum':v['Sum']} for p,v in expected.items()], 'Settings':[{'Key':'vcs','Value':'git'},{'Key':'vcs.revision','Value':'1'*40},{'Key':'vcs.modified','Value':'false'}]}
        o.compiled_modules(info,expected,'1'*40)
        for mode in ('version','path','missing','replace','empty-replace','duplicate','sum'):
            bad=copy.deepcopy(info)
            if mode=='version':bad['GoVersion']='go1.26.9'
            elif mode=='path':bad['Path']='wrong'
            elif mode=='missing':bad['Deps'].pop()
            elif mode=='duplicate':bad['Deps'].append(bad['Deps'][0])
            elif mode=='sum':bad['Deps'][0]['Sum']='bad'
            else:bad['Deps'][0]['Replace']={} if mode=='empty-replace' else {'Path':'local'}
            with self.assertRaises(ValueError):o.compiled_modules(bad,expected,'1'*40)
        for mode in ('missing','duplicate','revision','dirty','backend','untyped'):
            bad=copy.deepcopy(info)
            if mode=='missing':del bad['Settings']
            elif mode=='duplicate':bad['Settings'].append(bad['Settings'][0])
            elif mode=='revision':bad['Settings'][1]['Value']='2'*40
            elif mode=='dirty':bad['Settings'][2]['Value']='true'
            elif mode=='backend':bad['Settings'][0]['Value']='other'
            else:bad['Settings'][2]['Value']=False
            with self.assertRaises(ValueError):o.compiled_modules(bad,expected,'1'*40)
        directory=o.ROOT/o.ADAPTER
        with patch.object(o,'execute',return_value=SimpleNamespace(stdout=b'{"GoFiles":["card.go","fixture.go","main.go"]}')):self.assertEqual(set(o.compiler_inputs('go',directory,{})),set(o.SOURCE_FILES))
        with patch.object(o,'execute',return_value=SimpleNamespace(stdout=b'{"GoFiles":["main.go"]}')),self.assertRaises(ValueError):o.compiler_inputs('go',directory,{})

    def test_orchestration_and_recomputed_evidence_mocks_are_not_native(self):
        expected=o.subject()['modules'];info={'GoVersion':'go1.26.8','Path':'github.com/sage-x-project/sage-inspector/adapters/a2a-did-authority','Deps':[{'Path':p,'Version':v['Version'],'Sum':v['Sum']} for p,v in expected.items()], 'Settings':[{'Key':'vcs','Value':'git'},{'Key':'vcs.revision','Value':'1'*40},{'Key':'vcs.modified','Value':'false'}]}
        def command(cmd,*args,**kwargs):
            if cmd[1:] == ['version']:return SimpleNamespace(stdout=b'go version go1.26.8 linux/amd64\n')
            if cmd[1]=='build':Path(cmd[cmd.index('-o')+1]).write_bytes(b'synthetic-not-subject');return SimpleNamespace(stdout=b'')
            if cmd[1:4]==['version','-m','-json']:return SimpleNamespace(stdout=json.dumps(info).encode())
            if cmd[0]=='git':return SimpleNamespace(stdout=b'1'*40+b'\n')
            raise AssertionError(cmd)
        def process(cmd,input,**kwargs):
            return SimpleNamespace(stdout=json.dumps(native_rows()[0]['actual']).encode(),stderr=b'',returncode=0)
        with patch.object(o,'execute',side_effect=command),patch.object(o,'compiler_inputs',return_value={p:o.sha((o.ROOT/o.ADAPTER/p).read_bytes()) for p in o.SOURCE_FILES}),patch.object(o,'module_info',return_value=[{'Path':p,**v} for p,v in expected.items()]),patch.object(o.subprocess,'run',side_effect=process):
            import io
            attempts=io.StringIO();report=o.run_native('go',attempts=attempts)
            self.assertEqual(report['execution']['process_count'],2)
            from check_did_authority_evidence import verify,verify_native
            with tempfile.TemporaryDirectory() as tmp:
                d=Path(tmp);(d/'did-authority-revision.txt').write_text('1'*40+'\n');(d/'did-authority-tests.jsonl').write_bytes(encode(events()))
                def reset(value):
                    (d/'did-authority-native.json').write_text(json.dumps(value));(d/'did-authority-native.attempts.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in value['execution']['raw_trace']))
                reset(report);verify(d);verify(d)
                path=d/'did-authority-observation.json';fresh=o.load(path.read_bytes());fresh['cases'][0]['status']='PASS';path.write_text(json.dumps(fresh))
                with self.assertRaises(ValueError):verify(d)
                path.unlink()
                for field,value in [('status_counts',{'PASS':583}),('historical_results_merged',True),('unit_observations',unit_rows()),('fixture_sha256','0'*64)]:
                    bad=copy.deepcopy(report);bad[field]=value;reset(bad)
                    with self.assertRaises(ValueError):verify_native(d)
                for field,value in [('process_count',True),('adapter_sha256',''),('compiler','wrong')]:
                    bad=copy.deepcopy(report);bad['execution'][field]=value;reset(bad)
                    with self.assertRaises(ValueError):verify_native(d)
                bad=copy.deepcopy(report);bad['observer']['revision']='2'*40;reset(bad)
                with self.assertRaises(ValueError):verify_native(d)
                for mode in ('returncode','stdoutsha','rawboolean','attempts'):
                    bad=copy.deepcopy(report);raw=bad['execution']['raw_trace'][0]
                    if mode=='returncode':raw['returncode']=False
                    elif mode=='stdoutsha':raw['stdout_sha256']='0'*64
                    elif mode=='rawboolean':
                        value=o.load(bytes.fromhex(raw['stdout_hex']));value['client_calls']=True;data=o.canonical(value);raw['stdout_hex']=data.hex();raw['stdout_sha256']=o.sha(data)
                    reset(bad)
                    if mode=='attempts':(d/'did-authority-native.attempts.jsonl').write_text('')
                    with self.assertRaises(ValueError):verify_native(d)
            with patch.object(o.subprocess,'run',return_value=SimpleNamespace(stdout=b'',stderr=b'refused',returncode=1)),self.assertRaises(ValueError):o.run_native('go')

if __name__=='__main__':unittest.main()
