"""Non-HTTP MCP bytes over actual signed AEAD sessions; no remote host or tools."""
import argparse,copy,hashlib,itertools,json,subprocess,tempfile
from pathlib import Path
from test_completion010 import Actor,ROOT,ALICE,BOB,canonical,sign,verify,encode,decode,independent
from test_record010_adapters import PINS
VERSION='2025-06-18'
def sha(b):return hashlib.sha256(b).hexdigest()
def rpc_fixture():
    suite=json.loads((ROOT/'vectors/0.10.0/guard-rpc.json').read_bytes());v=json.loads(bytes.fromhex(suite['input']['envelope_hex']))['intent']
    v.update(issuer=ALICE,recipient=BOB,keyid=ALICE+'#signing-1',created=100,expires=400)
    policy=copy.deepcopy(suite['input']['approved_policy']);policy['issuer']=ALICE
    v['policy_digest']=sha(b'sage-policy|0.10.0\0'+canonical(policy))
    return dict(intent=v,proof=encode(sign(b'sage-execution-intent|0.10.0\0'+canonical(v),1)))
def response(intent,id,status):
    i=intent['intent'];r=dict(version='0.10.0',request_id=i['request_id'],call_id=i['call_id'],issuer=BOB,recipient=ALICE,created=100,expires=400,keyid=BOB+'#signing-1',alg='ed25519',intent_digest=sha(canonical(intent)),status=status,output={'value':'ok'} if status=='completed' else {})
    e=dict(result=r,proof=encode(sign(b'sage-tool-result|0.10.0\0'+canonical(r),2)))
    return dict(jsonrpc='2.0',id=id,result=dict(structuredContent=e,content=[dict(type='text',text=canonical(e).decode())],isError=status!='completed'))
def check_exchange(row,expected_intent):
    request=bytes.fromhex(row['rpc_hex']);received=bytes.fromhex(row['received_rpc_hex']);reply=bytes.fromhex(row['reply_rpc_hex']);opened=bytes.fromhex(row['opened_reply_hex'])
    if request!=received or reply!=opened:raise ValueError('RPC bytes changed')
    q=json.loads(request);r=json.loads(reply);outer=json.loads(bytes.fromhex(row['request_wire_hex']));answer=json.loads(bytes.fromhex(row['response_wire_hex']))
    expected_request=dict(jsonrpc='2.0',id=row['rpc_id'],method='tools/call',params=dict(name='sage_secure_call',arguments=dict(envelope=expected_intent)))
    if q!=expected_request:raise ValueError('unexpected protected request')
    if q['id']!=row['rpc_id'] or r['id']!=q['id'] or outer['id']==q['id'] or answer['message_id']!=outer['id']:raise ValueError('invocation binding')
    if outer['did']!=ALICE or outer['recipient']!=BOB or answer['did']!=BOB or answer['recipient']!=ALICE:raise ValueError('peer binding')
    if outer['encoding']!='session' or answer['encoding']!='session' or answer['request_hash']!=encode(hashlib.sha256(canonical(outer)).digest()):raise ValueError('record binding')
    result=r['result']['structuredContent']['result'];intent=q['params']['arguments']['envelope']
    if result['intent_digest']!=sha(canonical(intent)) or result['status']!=row['status']:raise ValueError('intent/result binding')
    envelope=r['result']['structuredContent']
    if set(r)!={'jsonrpc','id','result'} or r['jsonrpc']!='2.0' or r['result']!=dict(structuredContent=envelope,content=[dict(type='text',text=canonical(envelope).decode())],isError=row['status']!='completed'):raise ValueError('MCP result mapping')
    if result['issuer']!=BOB or result['recipient']!=ALICE or result['request_id']!=expected_intent['intent']['request_id'] or result['call_id']!=expected_intent['intent']['call_id']:raise ValueError('result identity')
    want='unavailable' if row['status']=='pending' else ''
    if answer['success']!=(row['status']=='completed') or answer.get('error','')!=want:raise ValueError('status mapping')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('go','rust','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--development',action='store_true');a=p.parse_args();out=a.output.resolve()
    if out.is_relative_to(ROOT/'docs/evidence'):p.error('preserve historical evidence')
    out.mkdir(parents=True,exist_ok=False);programs={n:getattr(a,n).resolve(strict=True) for n in PINS}
    report=dict(kind='mcp-session-binding',status='RUNNING',conformance='NOT_ESTABLISHED',lifecycle=dict(NOT_RUN=37),development=a.development,dispatch='NOT_RUN',durable_client_consumption='NOT_RUN',initialize_negotiation='TRUSTED_TEST_CONFIGURATION',replay_store='IN_MEMORY_TEST_STORE',registry_source='CONTROLLED_TEST_SOURCE',subjects={},exchanges=[],processes=8,files={},inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip())
    audit=[];logfile=(out/'raw.jsonl').open('x')
    def log(value):
        logfile.write(json.dumps(value)+'\n');logfile.flush()
        if 'exit_code' in value and (value['exit_code'] or value['stderr'] or value['stdout_tail']):raise ValueError('process exit or output mismatch')
    def retain(name,raw):(out/name).write_bytes(raw);report['files'][name]=sha(raw)
    def signature(message,sig,key):verify(message,sig,key);audit.append(dict(message_hex=message.hex(),signature_hex=sig.hex(),public_fixture_key=key))
    try:
        for n,binary in programs.items():
            repo=ROOT.parent/('sage' if n=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            if not a.development and rev!=PINS[n]:raise ValueError('unreviewed core revision')
            report['subjects'][n]=dict(revision=rev,adapter_sha256=sha(binary.read_bytes()))
        intent=rpc_fixture();retain('intent.json',canonical(intent))
        with tempfile.TemporaryDirectory() as folder:
            tmp=Path(folder)
            for left,right in itertools.product(programs,repeat=2):
                label=left+'-to-'+right;ap=tmp/(label+'-alice');bp=tmp/(label+'-bob')
                alice=Actor(label+'-a','alice',ap,programs[left],log);bob=Actor(label+'-b','bob',bp,programs[right],log)
                try:
                    hq=alice.call('start')['wire_hex'];hr=bob.call('respond',wire_hex=hq)['wire_hex'];alice.call('complete',wire_hex=hr);independent(bytes.fromhex(hq),bytes.fromhex(hr))
                    entries=[]
                    for n,status in enumerate(('pending','completed'),1):
                        id='00000000-0000-4000-8000-'+str(100+n).zfill(12)
                        q=dict(jsonrpc='2.0',id=id,method='tools/call',params=dict(name='sage_secure_call',arguments=dict(envelope=intent)))
                        raw=b' '+canonical(q)+b'\n';rq=alice.call('mcp-seal',target=VERSION,message_id=id,wire_hex=raw.hex(),unix=100+n,mono_ms=n*1000)['wire_hex']
                        got=bob.call('mcp-open',target=VERSION,wire_hex=rq,unix=100+n,mono_ms=n*1000)
                        if got!={'rpc_id':id,'rpc_hex':raw.hex()}:raise ValueError('protected request changed')
                        bob.call('mcp-open','REJECT',target=VERSION,wire_hex=rq,unix=100+n,mono_ms=n*1000)
                        reply=b' '+canonical(response(intent,id,status))+b'\n';rs=bob.call('mcp-reply',message_id=id,wire_hex=reply.hex(),unix=100+n,mono_ms=n*1000)['wire_hex']
                        bob.call('mcp-reply','REJECT',message_id=id,wire_hex=reply.hex(),unix=100+n,mono_ms=n*1000)
                        entries.append(dict(pair=label,rpc_id=id,status=status,rpc_hex=raw.hex(),received_rpc_hex=got['rpc_hex'],reply_rpc_hex=reply.hex(),request_wire_hex=rq,response_wire_hex=rs))
                    alice.call('mcp-open-reply','REJECT',message_id=entries[0]['rpc_id'],wire_hex=entries[1]['response_wire_hex'],unix=102,mono_ms=2000)
                    for row in entries:
                        row['opened_reply_hex']=alice.call('mcp-open-reply',message_id=row['rpc_id'],wire_hex=row['response_wire_hex'],unix=102,mono_ms=2000)['wire_hex']
                        alice.call('mcp-open-reply','REJECT',message_id=row['rpc_id'],wire_hex=row['response_wire_hex'],unix=102,mono_ms=2000)
                        check_exchange(row,intent);report['exchanges'].append(row)
                        for name,key,domain in [('request_wire_hex',1,b'sage-wire-request|0.10.0\n'),('response_wire_hex',2,b'sage-wire-response|0.10.0\n')]:
                            v=json.loads(bytes.fromhex(row[name]));sig=decode(v.pop('signature'));signature(domain+canonical(v),sig,key)
                        signature(b'sage-execution-intent|0.10.0\0'+canonical(intent['intent']),decode(intent['proof']),1)
                        result=json.loads(bytes.fromhex(row['reply_rpc_hex']))['result']['structuredContent'];signature(b'sage-tool-result|0.10.0\0'+canonical(result['result']),decode(result['proof']),2)
                finally:
                    try:alice.close()
                    finally:bob.close()
                    for name,path in [('alice',ap),('bob',bp)]:
                        if path.exists():retain(label+'-'+name+'.journal',path.read_bytes())
        retain('signature-audit.json',canonical(audit));report['signature_checks']=len(audit);report['status']='PASS'
    except Exception:
        report['status']='FAIL';raise
    finally:
        logfile.close();report['files']['raw.jsonl']=sha((out/'raw.jsonl').read_bytes());(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: four language pairs, eight session processes and 32 independent signature checks; dispatch not claimed')
if __name__=='__main__':main()
