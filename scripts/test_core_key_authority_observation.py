"""Memory-only parser controls; stored public frames are not fresh execution."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519
import core_key_authority_observation as o


def enc(raw): return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def rows(language):
    path = o.ROOT/o.BASE/'parser-calibrations.json'
    data = o.load(path.read_bytes())
    return copy.deepcopy(data['observations'][language])


def replace_request(w, value, resign=True):
    if resign:
        value['signature'] = enc(ed25519.Ed25519PrivateKey.from_private_bytes(bytes([1])*32).sign(b'sage-wire-request|0.10.0\n'+o.canonical({k:v for k,v in value.items() if k != 'signature'})))
    raw = o.canonical(value); w.update(request_b64=enc(raw),request_sha256=o.sha(raw))


def go_events(observed=None):
    result = [{'Action':'start','Package':o.PACKAGE},{'Action':'run','Package':o.PACKAGE,'Test':o.PARENT}]
    for case,w in sorted((rows('go') if observed is None else observed).items()):
        name = o.PARENT+'/'+case; result.append({'Action':'run','Package':o.PACKAGE,'Test':name})
        line = '    witness: '+o.MARKER+json.dumps(w)+'\n'
        pieces = [line[:25]]+[line[i:i+1024] for i in range(25,len(line),1024)]
        result += [{'Action':'output','Package':o.PACKAGE,'Test':name,'Output':part} for part in pieces]
        result.append({'Action':'pass','Package':o.PACKAGE,'Test':name})
    return result+[{'Action':'pass','Package':o.PACKAGE,'Test':o.PARENT},{'Action':'pass','Package':o.PACKAGE}]


def stream(events): return b''.join(json.dumps(row).encode()+b'\n' for row in events)


def rust_text(observed=None):
    found = rows('rust') if observed is None else observed
    lines = ['','running 3 tests']
    for name,cases in sorted(o.RUST_TESTS.items()):
        output = [o.MARKER+json.dumps(found[case]) for case in sorted(cases) if case in found]
        lines.append('test '+o.RUST_PREFIX+name+' ... '+(output[0] if output else ''))
        lines += output[1:]+['ok']
    return ('\n'.join(lines)+'\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 650 filtered out; finished in 0.01s\n\n').encode()


class CoreKeyAuthorityTests(unittest.TestCase):
    def test_complete_paired_report_and_no_history_union(self):
        for language in ['go','rust']:
            for w in rows(language).values(): self.assertEqual(o.witness(w,language),w)
        report = o.assess(rows('go'),rows('rust'))
        self.assertEqual(report['status_counts'],{'PARTIAL':2,'NOT_RUN':581})
        self.assertFalse(report['historical_results_merged']); self.assertEqual(report['scope']['peer_document_parser'],'NOT_EXPOSED')
        self.assertEqual(o.assess({}, {})['status_counts'],{'NOT_RUN':583})
        for lang in ['go','rust']:
            for case in o.CASES:
                go,rust=rows('go'),rows('rust');del (go if lang=='go' else rust)[case]
                self.assertEqual(o.assess(go,rust)['status_counts'],{'NOT_RUN':583})

    def test_witness_identity_scope_strict_results_and_types(self):
        for language in ['go','rust']:
            original=rows(language)['normal']
            for key,value in [('extra','PASS'),('schema','other'),('case','unknown'),('scope','operating'),('peer_document_parser','SUPPORTED'),('operating_registry','BOUND'),('deployed_custody','BOUND'),('session_returned',1),('application_request_opened',True),('application_response_opened',False),('request_replay_refused',1),('response_reuse_refused',False)]:
                bad=copy.deepcopy(original);bad[key]=value
                with self.subTest(lang=language,key=key),self.assertRaises(ValueError):o.witness(bad,language)
            bad=rows(language)['source-error'];bad['session_returned']=0
            with self.assertRaises(ValueError):o.witness(bad,language)
        with self.assertRaises(ValueError):o.witness(rows('go')['normal'],'other')

    def test_resigned_request_semantic_drift_and_joint_hash_edits(self):
        original=rows('go')['normal'];request=o.document(o.decode(original['request_b64']))
        for key,value in [('role','responder'),('did',o.B),('kid',o.A+'#signing-2'),('recipient',o.A),('version','0.11.0'),('encoding','session'),('created',True),('expires',401),('nonce','AB'),('id','not-uuid')]:
            bad=copy.deepcopy(original);value_map=copy.deepcopy(request);value_map[key]=value;replace_request(bad,value_map)
            with self.subTest(key=key),self.assertRaises(ValueError):o.witness(bad,'go')
        bad=copy.deepcopy(original);value_map=copy.deepcopy(request);value_map['nonce']=enc(bytes(16));replace_request(bad,value_map,False)
        with self.assertRaises(ValueError):o.witness(bad,'go')
        for value in ['00'*32,True]:
            bad=copy.deepcopy(original);bad['request_sha256']=value
            with self.assertRaises(ValueError):o.witness(bad,'go')
        # Equivalent outer JSON formatting preserves canonical signatures/hash correlation.
        bad=copy.deepcopy(original);raw=json.dumps(request,indent=2).encode();bad.update(request_b64=enc(raw),request_sha256=o.sha(raw))
        self.assertEqual(o.witness(bad,'go'),bad)

    def test_initiation_profile_and_exact_added_member(self):
        for case in ['normal','outer/didDocument','initiation/alsoKnownAs','initiation/canonicalId']:
            original=rows('go')[case];request=o.document(o.decode(original['request_b64']));inner=o.document(o.decode(request['payload']))
            for key,value in [('v','0.11.0'),('task','other'),('respKid',o.B+'#signing-2'),('kemKid',o.B+'#signing-1'),('ctx','other'),('nonce',enc(bytes(16))),('ephC','AA')]:
                bad=copy.deepcopy(original);wire=copy.deepcopy(request);changed=copy.deepcopy(inner);changed[key]=value;wire['payload']=enc(o.canonical(changed));replace_request(bad,wire)
                with self.subTest(case=case,key=key),self.assertRaises(ValueError):o.witness(bad,'go')
            bad=copy.deepcopy(original);wire=copy.deepcopy(request);wire['payload']=enc(json.dumps(inner,indent=2).encode());replace_request(bad,wire)
            with self.assertRaises(ValueError):o.witness(bad,'go')
        for case in o.CLOSED:
            bad=rows('go')[case];wire=o.document(o.decode(bad['request_b64']));site,name=case.split('/')
            if site=='outer':wire[name]={'unrelated':'value'}
            else:
                inner=o.document(o.decode(wire['payload']));inner[name]=False;wire['payload']=enc(o.canonical(inner))
            replace_request(bad,wire)
            with self.assertRaises(ValueError):o.witness(bad,'go')

    def test_authored_source_keys_digest_version_state_and_phase(self):
        for lang in ['go','rust']:
            for case in ['normal','matched-kem-2','revoke-init','revoke-resp','source-error','local-signing-mismatch']:
                original=rows(lang)[case]
                for mutation in ['reorder','version','key','digest','source','ready','extra','nullable-expiry','missing-S2']:
                    bad=copy.deepcopy(original)
                    target=next(r['snapshot'] for r in bad['source_reads'] if 'snapshot' in r)
                    if mutation=='reorder':bad['source_reads'][0],bad['source_reads'][1]=bad['source_reads'][1],bad['source_reads'][0]
                    elif mutation=='version':target['version']='9'
                    elif mutation=='key':target['keys'][0]['material']='00'*32;target['digest']=o.sha(o.canonical(target['keys']))
                    elif mutation=='digest':target['digest']='00'*32
                    elif mutation=='source':target['source']='other-authority'
                    elif mutation=='ready':target['ready']=1
                    elif mutation=='extra':target['controller']='invented'
                    elif mutation=='nullable-expiry':target['keys'][0]['expires']=None;target['digest']=o.sha(o.canonical(target['keys']))
                    else:target['keys'].pop();target['digest']=o.sha(o.canonical(target['keys']))
                    with self.subTest(lang=lang,case=case,mutation=mutation),self.assertRaises(ValueError):o.witness(bad,lang)
            for case in ['revoke-init','revoke-resp']:
                bad=rows(lang)[case]
                target=next(r['snapshot'] for r in bad['source_reads'] if 'snapshot' in r and any(k['state']=='revoked' for k in r['snapshot']['keys']))
                for key in target['keys']:key['state']='accepted'
                target['digest']=o.sha(o.canonical(target['keys']))
                with self.assertRaises(ValueError):o.witness(bad,lang)
            bad=rows(lang)['source-error'];bad['source_reads'][-1]['snapshot']=o.snapshot('normal','server',o.A)
            with self.assertRaises(ValueError):o.witness(bad,lang)
            for action in ['overwrite','delete']:
                bad=rows(lang)['matched-kem-2'];target=next(r['snapshot'] for r in bad['source_reads'] if r['requested_did']==o.B)
                if action=='overwrite':target['keys'][0]['material']=o.public(7,'x25519').hex()
                else:target['keys'].pop(0)
                target['digest']=o.sha(o.canonical(target['keys']))
                with self.assertRaises(ValueError):o.witness(bad,lang)

    def test_completion_transcript_tuple_signatures_and_application(self):
        for language in ['go','rust']:
            original=rows(language)['normal']
            for key,value in [('th',enc(bytes(32))),('sid',enc(bytes(16))),('kemKid',o.B+'#kem-2'),('kid','bad'),('extra','wrong')]:
                bad=copy.deepcopy(original);bad['tuple'][key]=value
                with self.assertRaises(ValueError):o.witness(bad,language)
            for field in ['completion_b64','application_request_b64','application_response_b64']:
                bad=copy.deepcopy(original);value=o.document(o.decode(bad[field]));value['signature']=enc(bytes(64));bad[field]=enc(o.canonical(value))
                with self.assertRaises(ValueError):o.witness(bad,language)
            for field,key,value in [('completion_b64','message_id','11111111-1111-4111-8111-111111111111'),('application_response_b64','request_hash',enc(bytes(32))),('application_request_b64','session_id',enc(bytes(16)))]:
                bad=copy.deepcopy(original);wire=o.document(o.decode(bad[field]));wire[key]=value;responder=field!='application_request_b64'
                wire['signature']=enc(ed25519.Ed25519PrivateKey.from_private_bytes(bytes([2 if responder else 1])*32).sign((b'sage-wire-response|0.10.0\n' if responder else b'sage-wire-request|0.10.0\n')+o.canonical({k:v for k,v in wire.items() if k!='signature'})));bad[field]=enc(o.canonical(wire))
                with self.assertRaises(ValueError):o.witness(bad,language)
            for mutation in ['task','sigB64','transcript','ackTagB64','noncanonical']:
                bad=copy.deepcopy(original);wire=o.document(o.decode(bad['completion_b64']));done=o.document(o.decode(wire['data']))
                if mutation=='transcript':done['transcript']['enc']=enc(bytes(32))
                elif mutation!='noncanonical':done[mutation]='wrong'
                if mutation!='sigB64':done['sigB64']=enc(ed25519.Ed25519PrivateKey.from_private_bytes(bytes([2])*32).sign(b'sage-hpke-complete|0.10.0\n'+o.canonical({k:v for k,v in done.items() if k!='sigB64'})))
                wire['data']=enc(json.dumps(done,indent=2).encode() if mutation=='noncanonical' else o.canonical(done));wire['signature']=enc(ed25519.Ed25519PrivateKey.from_private_bytes(bytes([2])*32).sign(b'sage-wire-response|0.10.0\n'+o.canonical({k:v for k,v in wire.items() if k!='signature'})));bad['completion_b64']=enc(o.canonical(wire))
                with self.assertRaises(ValueError):o.witness(bad,language)

    def test_replay_result_and_prefix_scope(self):
        for field,value in [('server_replay_entries',True),('server_replay_entries',3),('handshake_server_replay_entries',5)]:
            bad=rows('go')['normal'];bad[field]=value
            with self.assertRaises(ValueError):o.witness(bad,'go')
        original=rows('rust')['normal']
        for mode in ['count','order','context','handshake-prefix','source-prefix','extra-context']:
            bad=copy.deepcopy(original)
            if mode=='count':bad['replay_publications'][0]['retained_entries']=True
            elif mode=='order':bad['replay_publications'].reverse()
            elif mode=='context':bad['replay_publications'][0]['context']='wrong'
            elif mode=='handshake-prefix':bad['handshake_replay_publications'].pop()
            elif mode=='source-prefix':bad['handshake_source_reads']=bad['source_reads']
            else:bad['replay_publications'][-1]['context']=''
            with self.assertRaises(ValueError):o.witness(bad,'rust')
        bad=rows('rust')['source-error'];bad['replay_publications']=[{}]
        with self.assertRaises(ValueError):o.witness(bad,'rust')

    def test_exact_go_fragmented_stream_attribution(self):
        self.assertEqual(o.go_witnesses(stream(go_events())),rows('go'))
        timed=go_events();timed[-1]['Elapsed']=0.01;self.assertEqual(o.go_witnesses(stream(timed)),rows('go'))
        timed[-1]['Elapsed']=True
        with self.assertRaises(ValueError):o.go_witnesses(stream(timed))
        variants=[]
        value=go_events();value.pop();variants.append(value)
        value=go_events();value.insert(1,copy.deepcopy(value[1]));variants.append(value)
        value=go_events();value[2]['Test']='Other';variants.append(value)
        value=go_events();value[0]['Package']='Other';variants.append(value)
        value=go_events();value[2]['Action']='skip';variants.append(value)
        value=go_events();entry=next(r for r in value if r.get('Output'));entry['Test']=o.PARENT;variants.append(value)
        value=go_events();entry=next(r for r in value if r.get('Output'));entry['Output']='x'*4097;variants.append(value)
        value=go_events();value.insert(-2,{'Action':'output','Package':o.PACKAGE,'Output':'truncated'});variants.append(value)
        value=go_events();entries=[r for r in value if r.get('Output')];entries[0]['Output']=o.MARKER+'{}\n';variants.append(value)
        value=go_events();value.insert(1,{'Action':'pass','Package':o.PACKAGE,'Test':o.PARENT});variants.append(value)
        value=go_events();first=next(r['Test'] for r in value if r.get('Output'));outputs=[r for r in value if r.get('Test')==first and r['Action']=='output'];value=[r for r in value if r not in outputs];terminal=next(i for i,r in enumerate(value) if r.get('Test')==first and r['Action']=='pass');value[terminal+1:terminal+1]=outputs;variants.append(value)
        value=go_events();value.append({'Action':'output','Package':o.PACKAGE,'Output':'after terminal\n'});variants.append(value)
        for value in variants:
            with self.assertRaises((ValueError,KeyError)):o.go_witnesses(stream(value))
        with self.assertRaises(ValueError):o.go_witnesses(stream(go_events())[:-1])
        with self.assertRaises(ValueError):o.go_witnesses(b'{"Action":"pass","Action":"start"}\n')
        missing=rows('go');missing.pop('normal')
        with self.assertRaises(ValueError):o.go_witnesses(stream(go_events(missing)))

    def test_exact_rust_serial_boundary_and_summary(self):
        raw=rust_text();self.assertEqual(o.rust_witnesses(raw),rows('rust'))
        for changed in [raw.rstrip(b'\n'),raw.replace(b'3 passed',b'2 passed'),raw.replace(b'0 ignored',b'1 ignored'),raw.replace(b'running 3 tests',b'running 4 tests'),raw.replace(b'current_source ...',b'other ...'),raw.replace(b'\nok\n',b'\nFAILED\n',1),raw+raw,raw+ b'\ntest unapproved ... ok\n']:
            with self.assertRaises(ValueError):o.rust_witnesses(changed)
        value=rows('rust');value.pop('normal')
        with self.assertRaises(ValueError):o.rust_witnesses(rust_text(value))
        value=rows('rust');value['normal']['case']='revoke-init'
        with self.assertRaises(ValueError):o.rust_witnesses(rust_text(value))
        with self.assertRaises(ValueError):o.rust_witnesses(o.MARKER.encode()+b'{}\n')

    def test_json_base64_shapes_and_fixture_subject_drift(self):
        for raw in [b'{}'*20000,b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1.25}',b'{"x":"\xc3\xa9"}']:
            with self.assertRaises(ValueError):o.document(raw)
        for value in ['','AA=','AB','A','*',None,False]:
            with self.assertRaises(ValueError):o.decode(value)
        with self.assertRaises(ValueError):o.decode('AA',2)
        with self.assertRaises(ValueError):o.closed([],set(),'object')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for path in [o.SUBJECT,o.FIXTURE]:
                target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text('{}')
            with self.assertRaises(ValueError):o.subject(root)
            with self.assertRaises(ValueError):o.fixtures(root)
        self.assertEqual(len(o.subject()['go']['sources']),148);self.assertEqual(len(o.subject()['rust']['sources']),57)
        self.assertEqual(set(o.fixtures()['mapping']),o.GROUPS)
        self.assertTrue(o.observer_sources())


if __name__ == '__main__':unittest.main()
