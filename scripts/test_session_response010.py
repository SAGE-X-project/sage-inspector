"""Bounded signed session response exchanges over local core CLI processes."""
import argparse,hashlib,itertools,json,subprocess,tempfile
from pathlib import Path
from test_completion010 import Actor,ROOT,canonical,encode,decode,sign,verify,independent,digest,ALICE,BOB
from test_record010_adapters import PINS
ERRORS=('authentication_failed','policy_denied','operation_failed','unavailable')
def changed(raw,request,kind,other,key):
 w=json.loads(raw);q=json.loads(request)
 if kind=='duplicate-field':return raw[:-1]+b',"success":true}'
 if kind=='signature':w['signature']=encode(bytes(64));return canonical(w)
 if kind=='request-hash':w['request_hash']=encode(bytes(32))
 elif kind=='message-id':w['message_id']='11111111-1111-4111-8111-111111111111'
 elif kind=='cross-request':w['message_id']=other
 elif kind=='same-id':w['id']=q['id']
 elif kind=='same-nonce':w['nonce']=q['nonce']
 elif kind in ('recipient','did','kid','role','context_id','session_id'):
  w[kind]={'recipient':BOB,'did':ALICE,'kid':BOB+'#different','role':'initiator','context_id':'11111111-1111-4111-8111-111111111111','session_id':encode(bytes(16))}[kind]
 elif kind=='tag':v=bytearray(decode(w['data']));v[-1]^=1;w['data']=encode(v)
 elif kind=='missing-error':w['success']=False;w.pop('error',None)
 elif kind=='unknown-error':w.update(success=False,error='other')
 elif kind=='success-error':w.update(success=True,error='policy_denied')
 elif kind=='success-type':w['success']='true'
 elif kind=='unknown-field':w['extra']='value'
 elif kind=='plain-encoding':w['encoding']='plain'
 else:return raw
 w.pop('signature');w['signature']=encode(sign(b'sage-wire-response|0.10.0\n'+canonical(w),key));return canonical(w)
def independent_response(request,response,key):
 q=json.loads(request);w=json.loads(response);sig=decode(w.pop('signature'));verify(b'sage-wire-response|0.10.0\n'+canonical(w),sig,key)
 assert w['message_id']==q['id'] and w['request_hash']==encode(hashlib.sha256(canonical(q)).digest())
 assert w['id']!=q['id'] and w['nonce']!=q['nonce'] and w['did']==q['recipient'] and w['recipient']==q['did']
 assert w['context_id']==q['context_id'] and w['session_id']==q['session_id'] and w['role']!=q['role'] and w['encoding']=='session'
 record=decode(w.pop('data'));assert len(record)>=36 and record[8:20]==bytes(4)+record[:8] and len(canonical(w))<=4033
 return int.from_bytes(record[:8],'big')
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for n in ('go','rust','output'):parser.add_argument('--'+n,type=Path,required=True)
 args=parser.parse_args();out=args.output.resolve()
 if ROOT/'docs/evidence' in (out,*out.parents):parser.error('preserve historical evidence')
 out.mkdir(parents=True,exist_ok=False);raw=(out/'raw.jsonl').open('w')
 def log(v):raw.write(json.dumps(v)+'\n');raw.flush()
 fixture=ROOT/'vectors/0.10.0/session-response010.json';f=json.loads(fixture.read_text());programs={n:getattr(args,n).resolve() for n in PINS}
 report=dict(kind='session-response010',status='RUNNING',conformance='NOT_ESTABLISHED',scope=f['scope'],fixture_sha256=digest(fixture),subjects={},scenarios=[],raw='raw.jsonl',inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip())
 def save():(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 save()
 try:
  for name,program in programs.items():
   repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip();assert rev==PINS[name];assert not subprocess.check_output(['git','diff','HEAD','--'],cwd=repo)
   p=repo/('pkg/agent/hpke/testdata/session-response010.json' if name=='go' else 'tests/fixtures/session-response010.json');assert digest(p)==digest(fixture)
   report['subjects'][name]=dict(revision=rev,executable_sha256=digest(program))
  assert len(f['cases'])==38
  with tempfile.TemporaryDirectory() as directory:
   tmp=Path(directory)
   for sender,receiver in itertools.product(programs,repeat=2):
    for kind in f['cases']:
     label=f'{sender}-to-{receiver}-{kind}';expiry=101 if kind=='key-expiry-during-commit' else 0
     alice=Actor(label+'-a','alice',tmp/(label+'-a'),programs[sender],log,expiry);bob=Actor(label+'-b','bob',tmp/(label+'-b'),programs[receiver],log,expiry)
     try:
      q=alice.call('start')['wire_hex'];r=bob.call('respond',wire_hex=q)['wire_hex'];alice.call('complete',wire_hex=r);independent(bytes.fromhex(q),bytes.fromhex(r))
      a,b,key=alice,bob,2
      request=bytes.fromhex(a.call('record-seal',wire_hex=b'request'.hex())['wire_hex']);b.call('record-open',wire_hex=request.hex())
      if kind=='reverse':
       a,b,key=b,a,1;request=bytes.fromhex(a.call('record-seal',wire_hex=b'reverse'.hex())['wire_hex']);b.call('record-open',wire_hex=request.hex())
      message_id=json.loads(request)['id'];code=kind if kind in ERRORS else '';data=b'' if kind=='empty-data' else b'result'
      control=dict(message_id=message_id,success=not code,error=code,wire_hex=data.hex())
      response=bytes.fromhex(b.call('response-seal',**control)['wire_hex']);b.call('response-seal','REJECT',**control);seq=independent_response(request,response,key)
      other_id='';other_response=b''
      if kind in ('cross-request','out-of-order'):
       other=bytes.fromhex(a.call('record-seal',wire_hex=b'other'.hex())['wire_hex']);b.call('record-open',wire_hex=other.hex());other_id=json.loads(other)['id'];other_response=bytes.fromhex(b.call('response-seal',message_id=other_id,success=True,wire_hex=b'other-result'.hex())['wire_hex']);independent_response(other,other_response,key)
      wire=changed(response,request,kind,other_id,key);accept=kind in ('valid','empty-data','reverse','out-of-order',*ERRORS);closed=False;mode={}
      if kind=='duplicate-terminal':a.call('response-open',wire_hex=response.hex())
      elif kind=='out-of-order':assert a.call('response-open',wire_hex=other_response.hex())['message_id']==other_id
      elif kind=='store-error':mode['mode']=kind
      elif kind in ('store-delay','revoke-init','revoke-resp','revoke-kem','source-error'):mode['mode']=kind;closed=True
      elif kind=='key-expiry-during-commit':mode['mode']='utc-delay';closed=True
      elif kind=='closed':a.call('close');closed=True
      elif kind=='expired':mode['unix']=400
      before=a.call('record-inspect')['reservations'];result=a.call('response-open','ACCEPT' if accept else 'REJECT',wire_hex=wire.hex(),**mode)
      assert a.call('record-inspect')==dict(state='CLOSED' if closed else 'ESTABLISHED',reservations=before+int(accept))
      expected=dict(message_id=message_id,success=not code,error=code,plaintext_hex=data.hex())
      if accept:assert result==expected;a.call('response-open','REJECT',wire_hex=response.hex(),**mode)
      elif not closed and kind not in ('duplicate-terminal','expired'):assert a.call('response-open',wire_hex=response.hex())==expected
      report['scenarios'].append(dict(id=label,status='PASS',response_seq=seq,independent_request_binding=True));save()
     finally:
      try:alice.close()
      finally:bob.close()
  report['status']='PASS'
 except Exception as e:report.update(status='FAIL',reason=str(e));raise
 finally:raw.close();report['raw_sha256']=digest(out/'raw.jsonl');save()
 print('152 session response scenarios passed across all four core combinations')
if __name__=='__main__':main()
