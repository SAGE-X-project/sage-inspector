"""Bounded local authenticated session requests; no network target or host bypass."""
import argparse,itertools,json,subprocess,tempfile,hashlib
from pathlib import Path
from test_completion010 import Actor,ROOT,canonical,encode,decode,sign,verify,independent,digest,ALICE,BOB
from test_record010_adapters import PINS

def mutate(wire,kind):
 if kind=='duplicate-field':return wire[:-1]+b',"version":"0.10.0"}'
 w=json.loads(wire)
 if kind=='signature':w['signature']=encode(bytes(64));return canonical(w)
 if kind=='tag':v=bytearray(decode(w['payload']));v[-1]^=1;w['payload']=encode(v)
 elif kind in ('did','recipient','kid','role','context_id','session_id','version'):
  w[kind]={'did':BOB,'recipient':ALICE,'kid':ALICE+'#different','role':'responder','context_id':'11111111-1111-4111-8111-111111111111','session_id':encode(bytes(16)),'version':'0.9.0'}[kind]
 elif kind=='unknown-field':w['extra']='value'
 else:return wire
 w.pop('signature');w['signature']=encode(sign(b'sage-wire-request|0.10.0\n'+canonical(w),1));return canonical(w)

def check_wire(wire,tuple_,key):
 w=json.loads(wire);sig=decode(w.pop('signature'));verify(b'sage-wire-request|0.10.0\n'+canonical(w),sig,key)
 assert w['encoding']=='session' and w['session_id']==tuple_['sid'] and w['context_id']==tuple_['ctx']
 record=decode(w.pop('payload'));seq=int.from_bytes(record[:8],'big');assert record[8:20]==bytes(4)+seq.to_bytes(8,'big') and seq<1000
 assert len(canonical(w))<=4033
 return seq

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('go','rust','output'):parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args();out=args.output.resolve()
 if ROOT/'docs/evidence' in (out,*out.parents):parser.error('preserve historical evidence')
 out.mkdir(parents=True,exist_ok=False);raw=(out/'raw.jsonl').open('w')
 def log(v):raw.write(json.dumps(v)+'\n');raw.flush()
 fixture=ROOT/'vectors/0.10.0/authenticated-record010.json';f=json.loads(fixture.read_text());programs={n:getattr(args,n).resolve() for n in PINS}
 report=dict(kind='authenticated-record010',status='RUNNING',conformance='NOT_ESTABLISHED',scope=f['scope'],fixture_sha256=digest(fixture),subjects={},scenarios=[],raw='raw.jsonl',inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip())
 def save():(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 save()
 try:
  for name,program in programs.items():
   repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip();assert rev==PINS[name],'unreviewed core';assert not subprocess.check_output(['git','diff','HEAD','--'],cwd=repo),'changed core'
   p=repo/('pkg/agent/hpke/testdata/authenticated-record010.json' if name=='go' else 'tests/fixtures/authenticated-record010.json');assert digest(p)==digest(fixture)
   report['subjects'][name]=dict(revision=rev,executable_sha256=digest(program))
  assert len(f['cases'])==32
  with tempfile.TemporaryDirectory() as directory:
   tmp=Path(directory)
   for sender,receiver in itertools.product(programs,repeat=2):
    for kind in f['cases']:
     label=f'{sender}-to-{receiver}-{kind}';expiry=101 if kind=='key-expiry-during-commit' else 0
     a=Actor(label+'-a','alice',tmp/(label+'-a'),programs[sender],log,expiry);b=Actor(label+'-b','bob',tmp/(label+'-b'),programs[receiver],log,expiry)
     try:
      q=a.call('start')['wire_hex'];r=b.call('respond',wire_hex=q);a.call('complete',wire_hex=r['wire_hex']);independent(bytes.fromhex(q),bytes.fromhex(r['wire_hex']))
      b.call('record-seal','REJECT',wire_hex=b'denied'.hex());assert b.call('record-inspect')==dict(state='RESPONSE_SENT',reservations=0)
      first=bytes.fromhex(a.call('record-seal',wire_hex=b'first'.hex())['wire_hex']);assert check_wire(first,r['tuple'],1)==0
      w=first;want=b'first'
      if kind in ('nonzero-first','out-of-order'):
       w=bytes.fromhex(a.call('record-seal',wire_hex=b'second'.hex())['wire_hex']);want=b'second';assert check_wire(w,r['tuple'],1)==1
      good=w;w=mutate(w,kind);controls={};accept=kind in ('valid','nonzero-first','out-of-order','application-reject','unrelated');closed=False;before=0
      if kind=='unrelated':controls['mode']='unrelated'
      if kind in ('duplicate','idle-expiry'):
       b.call('record-open',wire_hex=w.hex());before=1
       if kind=='idle-expiry':controls['mono_ms']=600000;closed=True
      elif kind in ('store-error','transport-id','transport-nonce'):controls['mode']=kind
      elif kind in ('store-delay','revoke-init','revoke-resp','revoke-kem','changed-material','source-error','clock-error'):controls['mode']=kind;closed=True
      elif kind=='pending-mono-expiry':controls['mono_ms']=300000;closed=True
      elif kind=='pending-utc-expiry':controls['unix']=400;closed=True
      elif kind=='key-expiry-during-commit':controls['mode']='utc-delay';closed=True
      elif kind=='closed':b.call('close');closed=True
      result=b.call('record-open','ACCEPT' if accept else 'REJECT',wire_hex=w.hex(),**controls)
      expected_state='CLOSED' if closed else 'ESTABLISHED' if accept or kind=='duplicate' else 'RESPONSE_SENT'
      assert b.call('record-inspect')==dict(state=expected_state,reservations=before+int(accept))
      if accept:
       assert result==dict(state='ESTABLISHED',plaintext_hex=want.hex());b.call('record-open','REJECT',wire_hex=w.hex(),**controls)
       if kind=='out-of-order':assert b.call('record-open',wire_hex=first.hex())['plaintext_hex']==b'first'.hex()
       # A later application rejection retains crypto state; no protected effect is invoked.
       reverse=bytes.fromhex(b.call('record-seal',wire_hex=b'rejection'.hex(),**controls)['wire_hex']);assert check_wire(reverse,r['tuple'],2)==0
       assert a.call('record-open',wire_hex=reverse.hex(),**controls)['plaintext_hex']==b'rejection'.hex()
      elif not closed and kind not in ('duplicate','transport-id','transport-nonce'):
       assert b.call('record-open',wire_hex=good.hex())==dict(state='ESTABLISHED',plaintext_hex=want.hex())
      report['scenarios'].append(dict(id=label,status='PASS',first_seq=check_wire(good,r['tuple'],1)));save()
     finally:
      try:a.close()
      finally:b.close()
  report['status']='PASS'
 except Exception as e:report.update(status='FAIL',reason=str(e));raise
 finally:raw.close();report['raw_sha256']=digest(out/'raw.jsonl');save()
 print('128 authenticated record scenarios passed across all four core combinations')
if __name__=='__main__':main()
