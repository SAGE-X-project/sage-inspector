"""Synthetic parser controls only; invalid mock crypto never counts as execution."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
import ingress_refusal_observation as o
from test_owned_http_observation import output as native_fixture


def enc(raw): return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def positive_frames():
    # Structurally framed but deliberately non-authentic signatures/ciphertext.
    request = {'context_id': '11111111-1111-4111-8111-111111111111', 'created': 100, 'did': o.PEER, 'encoding': 'session', 'expires': 130, 'id': '22222222-2222-4222-8222-222222222222', 'kid': o.PEER + '#sign', 'nonce': enc(bytes(16)), 'recipient': o.SERVER, 'role': 'initiator', 'session_id': enc(bytes([2])*16), 'signature': enc(bytes(64)), 'version': '0.10.0', 'payload': enc(bytes(64)), 'metadata': {'a2a_extensions': o.EXTENSION, 'a2a_version': '1.0'}}
    reply = {**request, 'did': o.SERVER, 'recipient': o.PEER, 'kid': o.SERVER+'#sign', 'role': 'responder', 'id': '33333333-3333-4333-8333-333333333333', 'nonce': enc(bytes([1])*16), 'data': request['payload'], 'message_id': request['id'], 'request_hash': enc(__import__('hashlib').sha256(o.canonical(request)).digest()), 'success': True}
    del reply['payload']; del reply['metadata']
    return pack(request), pack(reply, True)


def pack(value, response=False, changes=None):
    body = o.canonical(value)
    components = '"@status" "@method";req "@target-uri";req "@authority";req "content-digest";req "signature";req "x-sage-version";req "content-type" "content-digest" "x-sage-did" "x-sage-version"' if response else '"@method" "@target-uri" "@authority" "content-type" "content-digest" "x-sage-did" "x-sage-version"'
    headers = {'Connection':'close','Content-Length':str(len(body)),'Content-Type':'application/json','Content-Digest':'sha-256=:'+base64.b64encode(__import__('hashlib').sha256(body).digest()).decode()+':','Signature':'sig1=:'+base64.b64encode(bytes(64)).decode()+':','Signature-Input':'sig1=('+components+');keyid="'+value['kid']+'";alg="ed25519";created=100;expires=130;nonce="'+value['nonce']+'";tag="sage-0.10.0"','X-Sage-Did':value['did'],'X-Sage-Version':'0.10.0'}
    if not response:headers.update(Host='agents.example.com',**{'User-Agent':'Go-http-client/1.1'})
    if changes:headers.update(changes)
    return (('HTTP/1.1 200 OK' if response else 'POST /a2a HTTP/1.1')+'\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n').encode()+body


def memory_rows():
    result = {}
    for mode in o.MODES:
        h2,good=mode=='h2-only',mode=='positive-calibration'
        raw=b'' if h2 else (positive_frames()[0] if good else o.unsigned(mode)[0])
        response=positive_frames()[1] if good else (b'' if h2 else b'HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 22\r\nContent-Type: text/plain\r\n\r\nauthentication failed\n')
        calibration=None if good or h2 else {'scope':'separate-fresh-memory-fixture','parser_error':'','body_hex':o.unsigned(mode)[1].hex(),'open_error':'authentication failed','returned_request':False,'accepted_requests':0}
        result[mode]={'case':mode,'transport':'net.Pipe/TLS','target':o.TARGET,'server_did':o.SERVER,'local_did':o.SERVER,'peer_did':o.PEER,'source_did':o.SERVER,'source_version':'3','source_service':o.TARGET,'tls_name':'localhost','offered':['h2' if h2 else 'http/1.1'],'negotiated':'' if h2 else 'http/1.1','handshake_failed':h2,'handshake_error':'remote error: tls: no application protocol' if h2 else '','input_hex':raw.hex(),'input_sha256':o.sha(raw),'written':len(raw),'response_frame_hex':response.hex(),'response_status':200 if good else (0 if h2 else 401),'response_body_hex':(o.frame(response)[2].hex() if response else ''),'authenticated_response':good,'response_error':'' if good or h2 else 'authentication failed','verified_payload_hex':b'{"jsonrpc":"2.0","id":"one","result":{"ok":true}}'.hex() if good else '','verified_success':good,'verified_code':'','handler_calls':int(good),'handler_payloads_hex':[b'{"id":"one","jsonrpc":"2.0","method":"GetTask","params":{"id":"task"}}'.hex()] if good else [],'accepted_requests':int(good),'accepted_responses':int(good),'parser_trace':'NOT_REACHED' if h2 else 'NOT_OBSERVED','core_trace':'NOT_REACHED' if h2 else 'NOT_OBSERVED','calibration':calibration}
    return result


def native_rows():
    fixture=o.fixtures()['native'];case={'input':{'mode':'success'},'expected':{'outcome':'success','client_calls':1,'tls_handshakes':1,'handler_calls':1,'accepted_requests':1,'accepted_responses':1,'handler_payloads_hex':[fixture['request_hex']]}}
    actual=native_fixture(case,fixture)
    actual.update(verified_card_hex=actual['card_hex'],verified_did=o.owned.SERVER,verified_version='17',eligible_interfaces=[{'URL':actual['target'],'Tenant':''}])
    return {'bare':actual,'http':copy.deepcopy(actual)}


def events(rows=None):
    result=[{'Action':'start','Package':o.PACKAGE},{'Action':'run','Package':o.PACKAGE,'Test':o.PARENT}]
    for mode,w in sorted((rows or memory_rows()).items()):
        test=o.PARENT+'/'+mode
        result.append({'Action':'run','Package':o.PACKAGE,'Test':test})
        text='    witness: INGRESS_MEMORY_OBSERVATION '+json.dumps(w)+'\n'
        # Deliberately split inside the marker too, then into1024-byte chunks.
        pieces=[text[:24]]+[text[i:i+1024] for i in range(24,len(text),1024)]
        result += [{'Action':'output','Package':o.PACKAGE,'Test':test,'Output':part} for part in pieces]
        result.append({'Action':'pass','Package':o.PACKAGE,'Test':test})
    return result+[{'Action':'pass','Package':o.PACKAGE,'Test':o.PARENT},{'Action':'pass','Package':o.PACKAGE}]


def stream(rows):return b''.join(json.dumps(r).encode()+b'\n' for r in rows)


class IngressRefusalCheckerTests(unittest.TestCase):
    def test_complete_bounded_report_preserves_history(self):
        report=o.assess(memory_rows(),native_rows())
        self.assertEqual(report['status_counts'],{'PARTIAL':3,'NOT_RUN':580})
        self.assertFalse(report['historical_results_merged'])
        self.assertEqual(report['scope']['actual_grpc_SendMessage'],'NOT_OBSERVED')
        self.assertEqual(o.assess({}, {})['status_counts'],{'NOT_RUN':583})
        for mode in o.MODES:
            rows=memory_rows();del rows[mode]
            self.assertEqual(o.assess(rows,native_rows())['status_counts'],{'NOT_RUN':583})
        self.assertEqual(o.assess(memory_rows(),{'bare':native_rows()['bare']})['status_counts'],{'NOT_RUN':583})

    def test_memory_source_role_types_and_effects(self):
        base=memory_rows()['bare-jsonrpc']
        for key,value in [('extra','PASS'),('case','other'),('transport','tcp'),('target','https://evil.invalid'),('server_did',o.PEER),('peer_did',o.SERVER),('local_did',o.PEER),('source_did',o.PEER),('source_version','4'),('source_service','https://evil.invalid'),('tls_name','agents.example.com'),('handler_calls',True),('accepted_requests',True),('accepted_responses',1),('written',True),('authenticated_response',1),('verified_success',0),('verified_payload_hex','00'),('handler_payloads_hex',['00']),('parser_trace','CALLED'),('core_trace','CALLED'),('response_error','timeout')]:
            bad=copy.deepcopy(base);bad[key]=value
            with self.subTest(key=key),self.assertRaises((ValueError,TypeError)):o.memory(bad)

    def test_exact_unsigned_and_separate_calibration(self):
        for mode in ['bare-jsonrpc','legacy-unsigned','grpc-media-http1']:
            base=memory_rows()[mode]
            raw=bytes.fromhex(base['input_hex'])+b'changed';bad=copy.deepcopy(base);bad.update(input_hex=raw.hex(),input_sha256=o.sha(raw),written=len(raw))
            with self.assertRaises(ValueError):o.memory(bad)
            for key,value in [('scope','same-connection'),('parser_error','error'),('body_hex','00'),('open_error','timeout'),('returned_request',True),('accepted_requests',False)]:
                bad=copy.deepcopy(base);bad['calibration'][key]=value
                with self.subTest(mode=mode,key=key),self.assertRaises(ValueError):o.memory(bad)
            bad=copy.deepcopy(base);bad['response_frame_hex']=bad['response_frame_hex'].replace('343031','323030')
            with self.assertRaises(ValueError):o.memory(bad)

    def test_alpn_does_not_accept_timeout_or_hidden_http(self):
        base=memory_rows()['h2-only']
        for key,value in [('handshake_error','context deadline exceeded'),('handshake_error',''),('handshake_failed',False),('offered',['http/1.1']),('negotiated','h2'),('input_hex','00'),('response_frame_hex','00'),('response_body_hex','00'),('parser_trace','NOT_OBSERVED'),('core_trace','NOT_OBSERVED'),('calibration',{}),('response_status',401),('response_error','authentication failed')]:
            bad=copy.deepcopy(base);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):o.memory(bad)

    def test_positive_joint_body_hash_digest_mutations(self):
        base=memory_rows()['positive-calibration'];request,_=o.positive(bytes.fromhex(base['input_hex']))
        for key,value in [('did',o.SERVER),('recipient',o.PEER),('kid',o.PEER+'#kem'),('role','responder'),('version','0.11.0'),('created',True),('expires',131),('metadata',{}),('nonce','AA'),('signature','AA'),('payload','AA'),('id','invalid')]:
            altered=copy.deepcopy(request);altered[key]=value;raw=pack(altered)
            bad=copy.deepcopy(base);bad.update(input_hex=raw.hex(),input_sha256=o.sha(raw),written=len(raw))
            with self.subTest(key=key),self.assertRaises(ValueError):o.memory(bad)
        for key,value in [('Content-Type','text/plain'),('Content-Digest','sha-256=:AAAA:'),('X-Sage-Did',o.SERVER),('X-Sage-Version','0.11.0'),('Signature-Input','sig1=()'),('Signature','sig1=:AA==:')]:
            raw=pack(request,changes={key:value});bad=copy.deepcopy(base);bad.update(input_hex=raw.hex(),input_sha256=o.sha(raw),written=len(raw))
            with self.subTest(header=key),self.assertRaises(ValueError):o.memory(bad)

    def test_positive_response_correlation_and_verified_bytes(self):
        base=memory_rows()['positive-calibration'];reply,_=o.positive(bytes.fromhex(base['response_frame_hex']),True)
        for key,value in [('message_id','wrong'),('request_hash',enc(bytes(32))),('context_id','44444444-4444-4444-8444-444444444444'),('session_id',enc(bytes(16))),('success',1),('recipient',o.SERVER)]:
            altered=copy.deepcopy(reply);altered[key]=value;raw=pack(altered,True);bad=copy.deepcopy(base);bad.update(response_frame_hex=raw.hex(),response_body_hex=o.frame(raw)[2].hex())
            with self.subTest(key=key),self.assertRaises(ValueError):o.memory(bad)
        for key,value in [('verified_payload_hex','00'),('verified_success',False),('verified_code','BAD'),('handler_calls',0),('accepted_requests',0),('accepted_responses',0),('calibration',{})]:
            bad=copy.deepcopy(base);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):o.memory(bad)

    def test_fragmented_actual_attribution_contract(self):
        self.assertEqual(o.witnesses(stream(events())),memory_rows())
        variants=[]
        rows=events();rows.pop(-1);variants.append(rows)
        rows=events();rows.insert(-1,copy.deepcopy(rows[1]));variants.append(rows)
        rows=events();rows[2]['Test']='Other';variants.append(rows)
        rows=events();rows[0]['Package']='wrong';variants.append(rows)
        rows=events();rows[2]['Action']='skip';variants.append(rows)
        rows=events();next(r for r in rows if r.get('Output'))['Output']='INGRESS_MEMORY_OBSERVATION {}\n';variants.append(rows)
        rows=events();r=next(r for r in rows if r.get('Output'));r['Test']=o.PARENT;variants.append(rows)
        rows=events();rows[-1]['Action']='fail';variants.append(rows)
        for rows in variants:
            with self.assertRaises((ValueError,KeyError,TypeError)):o.witnesses(stream(rows))
        with self.assertRaises(ValueError):o.witnesses(stream(events())[:-1])
        rows=events();rows.insert(-2,{'Action':'output','Package':o.PACKAGE,'Test':o.PARENT,'Output':'truncated'})
        with self.assertRaises(ValueError):o.witnesses(stream(rows))
        rows=events();rows.insert(-2,{'Action':'output','Package':o.PACKAGE,'Output':'x'*4097})
        with self.assertRaises(ValueError):o.witnesses(stream(rows))
        duplicate=b'{"Action":"pass","Action":"start","Package":"'+o.PACKAGE.encode()+b'"}\n'
        with self.assertRaises(ValueError):o.witnesses(duplicate)

    def test_native_verified_source_and_phase_controls(self):
        base=native_rows()['bare'];fixture=o.fixtures()['native']
        self.assertTrue(o.native_match(base,fixture))
        for key,value in [('verified_card_hex','00'),('verified_did',o.owned.CALLER),('verified_version','18'),('eligible_interfaces',[]),('handler_calls',0),('accepted_responses',True),('source_reads',0),('setup_reservations',[True,1]),('records',[]),('extra','PASS')]:
            bad=copy.deepcopy(base);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):o.native_match(bad,fixture)
        with self.assertRaises(ValueError):o.assess({}, {'bad':base})

    def test_subject_fixture_and_package_source_drift(self):
        self.assertEqual(len(o.subject()['package_sources']),22)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for file in [o.SUBJECT,o.FIXTURE]:
                path=root/file;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('{}')
            with self.assertRaisesRegex(ValueError,'subject drift'):o.subject(root)
            with self.assertRaisesRegex(ValueError,'fixture drift'):o.fixtures(root)
            (root/'input').write_bytes(b'owned')
            self.assertEqual(o.selected_sources(root,{'input':o.sha(b'owned')}),{'input':o.sha(b'owned')})
            with self.assertRaises(ValueError):o.selected_sources(root,{'input':'0'*64})

    def test_compiled_native_modules_not_test_binary_claim(self):
        expected=o.subject()['modules'];info={'GoVersion':'go1.26.8','Path':'github.com/sage-x-project/sage-inspector/'+o.ADAPTER,'Deps':[{'Path':p,'Version':v['Version'],'Sum':v['Sum']} for p,v in expected.items()],'Settings':[{'Key':k,'Value':v} for k,v in {'vcs':'git','vcs.revision':'a'*40,'vcs.modified':'false'}.items()]}
        o.compiled_native(info,expected,'a'*40)
        for mode in ['compiler','path','missing','version','sum','replace','empty-replace','duplicate']:
            bad=copy.deepcopy(info)
            if mode=='compiler':bad['GoVersion']='go1.26.9'
            elif mode=='path':bad['Path']=o.PACKAGE+'.test'
            elif mode=='missing':bad['Deps'].pop()
            elif mode in ['replace','empty-replace']:bad['Deps'][0]['Replace']={} if mode=='empty-replace' else {'Path':'local'}
            elif mode=='duplicate':bad['Deps'].append(copy.deepcopy(bad['Deps'][0]))
            else:bad['Deps'][0][mode.title()]='wrong'
            with self.subTest(mode=mode),self.assertRaises(ValueError):o.compiled_native(bad,expected,'a'*40)

    def test_closed_ascii_http_and_canonical_encoding(self):
        for raw in [b'bad',b'GET / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 01\r\n\r\nx']:
            with self.assertRaises(ValueError):o.frame(raw)
        for value in ['0','AA=','gg','AB']:
            with self.assertRaises(ValueError):o.rawhex(value)
        for value in ['', 'AA=', 'AB']:
            with self.assertRaises(ValueError):o.b64(value)
        with self.assertRaises(ValueError):o.b64('AA',2)


    def test_request_hash_uses_canonical_signed_json(self):
        base=memory_rows()['positive-calibration'];request,_=o.positive(bytes.fromhex(base['input_hex']));reply,_=o.positive(bytes.fromhex(base['response_frame_hex']),True)
        pretty=json.dumps(request,indent=2).encode()
        start,headers,_=o.frame(bytes.fromhex(base['input_hex']))
        headers['content-length']=str(len(pretty));headers['content-digest']='sha-256=:'+base64.b64encode(__import__('hashlib').sha256(pretty).digest()).decode()+':'
        raw=(start+'\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n').encode()+pretty
        bad=copy.deepcopy(base);bad.update(input_hex=raw.hex(),input_sha256=o.sha(raw),written=len(raw))
        # A noncanonical wire spelling still correlates through JCS, not wire SHA.
        self.assertTrue(o.memory(bad))
        reply['request_hash']=enc(__import__('hashlib').sha256(pretty).digest());response=pack(reply,True)
        bad.update(response_frame_hex=response.hex(),response_body_hex=o.frame(response)[2].hex())
        with self.assertRaisesRegex(ValueError,'correlation'):o.memory(bad)

    def test_unique_typed_build_settings_and_git_identity(self):
        self.assertEqual(o.build_settings({'Settings':[{'Key':'-race','Value':'true'}]}),{'-race':'true'})
        for value in [None,{}, {'Settings':None},{'Settings':[{}]},{'Settings':[{'Key':'-race','Value':True}]},{'Settings':[{'Key':1,'Value':'true'}]},{'Settings':[{'Key':'-race','Value':'true','extra':'ignored'}]},{'Settings':[{'Key':'-race','Value':'true'},{'Key':'-race','Value':'true'}]}]:
            with self.subTest(value=value),self.assertRaises(ValueError):o.build_settings(value)
        expected=o.subject()['modules'];base={'GoVersion':'go1.26.8','Path':'github.com/sage-x-project/sage-inspector/'+o.ADAPTER,'Deps':[{'Path':p,'Version':v['Version'],'Sum':v['Sum']} for p,v in expected.items()],'Settings':[{'Key':k,'Value':v} for k,v in {'vcs':'git','vcs.revision':'a'*40,'vcs.modified':'false'}.items()]}
        for key,value in [('vcs','hg'),('vcs.revision','b'*40),('vcs.modified','true')]:
            bad=copy.deepcopy(base);next(s for s in bad['Settings'] if s['Key']==key)['Value']=value
            with self.assertRaises(ValueError):o.compiled_native(bad,expected,'a'*40)
        for row in [{}, {'Path':True}, {'Path':'duplicate','Replace':{}}]:
            bad=copy.deepcopy(base);bad['Deps'].append(row)
            with self.assertRaises(ValueError):o.compiled_native(bad,expected,'a'*40)

    def test_memory_output_never_overwrites_existing_file_or_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);sentinel=root/'sentinel';sentinel.write_bytes(b'preserve actual earlier evidence')
            link=root/'linked-output';link.symlink_to(sentinel)
            dangling=root/'dangling-output';dangling.symlink_to(root/'missing')
            for output in [sentinel,link,dangling]:
                with self.assertRaisesRegex(ValueError,'exclusive'):o.public_test('go',o.ROOT,{},o.subject(),output)
            self.assertEqual(sentinel.read_bytes(),b'preserve actual earlier evidence')
            self.assertTrue(link.is_symlink());self.assertTrue(dangling.is_symlink());self.assertFalse((root/'missing').exists())

    def test_recheck_synthetic_bundle_rejects_execution_metadata_mutations(self):
        # Explicit parser fixture only: no compiler/process/crypto was executed.
        import contextlib,io
        import check_ingress_refusal_evidence as checker
        selected=o.subject();revision='a'*40;mem=memory_rows();nat=native_rows();raw=stream(events(mem));binary='/tmp/synthetic-ingress-test/ingress.test'
        report=o.assess(mem,nat)
        attempts=[{'id':key,'input_hex':o.canonical({'completion':key}).hex(),'input_sha256':o.sha(o.canonical({'completion':key})),'stdout_hex':o.canonical(value).hex(),'stdout_sha256':o.sha(o.canonical(value)),'stderr_hex':'','returncode':0} for key,value in nat.items()]
        native_info={'GoVersion':'go1.26.8','Path':'github.com/sage-x-project/sage-inspector/'+o.ADAPTER,'Deps':[{'Path':p,'Version':v['Version'],'Sum':v['Sum']} for p,v in selected['modules'].items()],'Settings':[{'Key':k,'Value':v} for k,v in {'vcs':'git','vcs.revision':revision,'vcs.modified':'false'}.items()]}
        inputs={'GoFiles':sorted(p.rsplit('/',1)[1] for p in selected['package_sources'] if p.endswith('.go') and not p.endswith('_test.go')),'TestGoFiles':sorted(p.rsplit('/',1)[1] for p in selected['package_sources'] if p.endswith('_test.go')),'XTestGoFiles':[],'EmbedFiles':['schema.json']}
        memory_meta={'download':{'Path':'github.com/sage-x-project/sage-adk',**selected['modules']['github.com/sage-x-project/sage-adk']},'package_source_sha256':selected['package_sources'],'package_inputs':inputs,'dependencies':[{'Path':p,**v} for p,v in selected['modules'].items() if p!='github.com/sage-x-project/sage-adk'],'test_binary_sha256':'0'*64,'build_info':{'GoVersion':'go1.26.8','Path':o.PACKAGE+'.test','Settings':[{'Key':'-race','Value':'true'}]},'build_command':['go','test','-mod=readonly','-race','-c','-o',binary,'./core/a2abinding'],'test_command':['go','tool','test2json','-t','-p',o.PACKAGE,binary,'-test.v=test2json','-test.run=^'+o.PARENT+'$','-test.count=1','-test.timeout=30s'],'execution_directory':'/tmp/synthetic-ingress-test/module','raw_test_sha256':o.sha(raw),'test_returncode':0,'test_stderr_hex':'','scope':'verified public module as test main; no compiled dependency metadata claim'}
        native_meta={'adapter_sha256':'1'*64,'adapter_source_sha256':{p:o.sha((o.ROOT/o.ADAPTER/p).read_bytes()) for p in ['main.go','fixture.go','card.go','go.mod','go.sum']},'modules':[{'Path':p,**v} for p,v in selected['modules'].items()],'build_info':native_info,'raw_trace':attempts,'process_count':2}
        report.update(evidence_kind='inspector-launched-memory-unit-and-separate-benign-native',observer={'repository':'SAGE-X-project/sage-inspector','revision':revision,'source_sha256':o.observer_sources()},execution={'memory':memory_meta,'native':native_meta})
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);(directory/'ingress-refusal-revision.txt').write_text(revision);(directory/'ingress-refusal-memory-tests.jsonl').write_bytes(raw);(directory/'ingress-refusal-native.attempts.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in attempts));path=directory/'ingress-refusal-native.json'
            def check(value):
                path.write_text(json.dumps(value))
                with contextlib.redirect_stdout(io.StringIO()):checker.verify(directory)
            check(report)
            for kind in ['public-sum','source','compile-input','command','raw-sha','test-code-bool','test-settings','native-settings','native-vcs','native-count','module-metadata','stdout','observer']:
                bad=copy.deepcopy(report);m=bad['execution']['memory'];n=bad['execution']['native']
                if kind=='public-sum':m['download']['Sum']='h1:'+('A'*43)+'='
                elif kind=='source':m['package_source_sha256']['go.mod']='0'*64
                elif kind=='compile-input':m['package_inputs']['GoFiles'].append('unbound.go')
                elif kind=='command':m['test_command'][-3]='-test.run=.'
                elif kind=='raw-sha':m['raw_test_sha256']='0'*64
                elif kind=='test-code-bool':m['test_returncode']=False
                elif kind=='test-settings':m['build_info']['Settings'].append({'Key':'-race','Value':'true'})
                elif kind=='native-settings':n['build_info']['Settings'].append({'Key':'vcs','Value':'git'})
                elif kind=='native-vcs':n['build_info']['Settings'][0]['Value']='hg'
                elif kind=='native-count':n['process_count']=True
                elif kind=='module-metadata':n['modules'][0]['GoModSum']='bad'
                elif kind=='stdout':n['raw_trace'][0]['stdout_sha256']='0'*64
                else:bad['observer']['source_sha256']['scripts/ingress_refusal_observation.py']='0'*64
                with self.subTest(kind=kind),self.assertRaises(ValueError):check(bad)


if __name__=='__main__':unittest.main()
