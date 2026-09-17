"""Bounded local signed handshakes; no remote target, production key or host bypass."""
import argparse,base64,copy,hashlib,itertools,json,os,select,subprocess,tempfile,time
from pathlib import Path
from test_record010_adapters import PINS
ROOT=Path(__file__).resolve().parents[1]
ALICE='did:sage:web:agent.example:alice';BOB='did:sage:web:agent.example:bob'
def encode(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def decode(s):return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
# Independent Node Ed25519 over fixed, explicitly public test seeds only.
NODE="""const c=require('crypto'),fs=require('fs');let q=JSON.parse(fs.readFileSync(0,'utf8'));if(![1,2].includes(q.key)||q.data.length>131072)process.exit(2);let k=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,q.key)]),format:'der',type:'pkcs8'});let b=Buffer.from(q.data,'hex');if(q.signature===undefined)process.stdout.write(c.sign(null,b,k).toString('hex'));else process.stdout.write(String(c.verify(null,b,c.createPublicKey(k),Buffer.from(q.signature,'hex'))));"""
def sign(data,key=2):return bytes.fromhex(subprocess.check_output(['node','-e',NODE],input=json.dumps(dict(key=key,data=data.hex())),text=True,timeout=10))
def verify(data,signature,key):assert subprocess.check_output(['node','-e',NODE],input=json.dumps(dict(key=key,data=data.hex(),signature=signature.hex())),text=True,timeout=10)=='true','independent signature failed'
def independent(request,response):
 q=json.loads(request);w=json.loads(response);signature=decode(q.pop('signature'));verify(b'sage-wire-request|0.10.0\n'+canonical(q),signature,1)
 q=json.loads(request);signature=decode(w.pop('signature'));verify(b'sage-wire-response|0.10.0\n'+canonical(w),signature,2)
 assert w['message_id']==q['id'] and w['request_hash']==encode(hashlib.sha256(canonical(q)).digest())
 init=json.loads(decode(q['payload']));c=json.loads(decode(w['data']));signature=decode(c.pop('sigB64'));verify(b'sage-hpke-complete|0.10.0\n'+canonical(c),signature,2)
 t=c['transcript'];assert all(t[k]==v for k,v in init.items());th=hashlib.sha256(canonical(t)).digest();sid=encode(hashlib.sha256(b'sage-session|0.10.0'+th).digest()[:16])
 return t,encode(th),sid

def changed(request,response,kind):
 if not kind:return response
 w=json.loads(response);q=json.loads(request);body=decode(w['data']);c=json.loads(body);inner=False
 if kind=='outer-signature':w['signature']=encode(bytes(64));return canonical(w)
 if kind=='inner-signature':c['sigB64']=encode(bytes(64))
 elif kind=='ack':c['ackTagB64']=encode(bytes(32));inner=True
 elif kind=='echo':c['transcript']['ctx']='11111111-1111-4111-8111-111111111111';inner=True
 elif kind=='request-hash':w['request_hash']=encode(bytes(32))
 elif kind=='message-id':w['message_id']='11111111-1111-4111-8111-111111111111'
 elif kind=='recipient':w['recipient']=BOB
 elif kind=='signing-key':w['kid']=BOB+'#different'
 elif kind=='response-nonce':w['nonce']=q['nonce']
 elif kind=='unknown-wire':w['extra']='value'
 elif kind=='unknown-completion':c['extra']='value'
 elif kind=='duplicate-wire':return response[:-1]+b',"version":"0.10.0"}'
 elif kind=='duplicate-completion':body=body[:-1]+b',"v":"0.10.0"}'
 elif kind=='duplicate-transcript':
  t=canonical(c['transcript']);body=body.replace(b'"transcript":'+t,b'"transcript":'+t[:-1]+b',"v":"0.10.0"}')
 elif kind=='null-transcript':c['transcript']=None
 elif kind=='trailing-wire':return response+b' {}'
 elif kind=='noncanonical-completion':body=b' '+body
 else:raise AssertionError(kind)
 if inner:c.pop('sigB64');c['sigB64']=encode(sign(b'sage-hpke-complete|0.10.0\n'+canonical(c)))
 if kind not in ('duplicate-completion','duplicate-transcript','noncanonical-completion'):body=canonical(c)
 w['data']=encode(body);w.pop('signature');w['signature']=encode(sign(b'sage-wire-response|0.10.0\n'+canonical(w)));return canonical(w)

class Actor:
 def __init__(self,name,role,path,program,log,expiry=0):
  self.name=name;self.log=log;self.expiry=expiry;self.index=0;self.buffer=b''
  self.p=subprocess.Popen([str(program),role,str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 def call(self,action,expected='ACCEPT',**controls):
  q=dict(id=str(self.index),action=action,mode='',mono_ms=0,unix=100,key_expires=self.expiry);q.update(controls);self.index+=1
  self.log(dict(actor=self.name,request=q));self.p.stdin.write(canonical(q)+b'\n');self.p.stdin.flush();deadline=time.monotonic()+15
  while b'\n' not in self.buffer:
   remaining=deadline-time.monotonic();assert remaining>0,'adapter timeout'
   ready,_,_=select.select([self.p.stdout],[],[],remaining);assert ready,'adapter timeout'
   data=os.read(self.p.stdout.fileno(),65536);assert data,'adapter closed before response';self.buffer+=data;assert len(self.buffer)<=256*1024,'output limit'
  line,self.buffer=self.buffer.split(b'\n',1);self.log(dict(actor=self.name,stdout=line.decode()))
  value=json.loads(line);assert set(value)=={'id','verdict','output'} and value['id']==q['id'] and value['verdict']==expected,(self.name,q['action'],value,expected)
  if expected=='REJECT':assert value['output']=={}
  return value['output']
 def close(self):
  try:out,err=self.p.communicate(timeout=10)
  except subprocess.TimeoutExpired:self.p.kill();out,err=self.p.communicate();raise AssertionError('adapter did not stop')
  finally:
   if self.p.poll() is None:self.p.kill();self.p.wait()
  self.log(dict(actor=self.name,exit_code=self.p.returncode,stdout_tail=(self.buffer+out).decode(errors='replace'),stderr=err.decode(errors='replace')))
  assert self.p.returncode==0 and not out and not self.buffer,'adapter termination failure'

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--go',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();output=args.output.resolve()
 if ROOT/'docs/evidence' in (output,*output.parents):parser.error('preserve historical evidence')
 output.mkdir(parents=True,exist_ok=False);programs={n:getattr(args,n).resolve() for n in PINS};fixture_path=ROOT/'vectors/0.10.0/completion010.json';fixture=json.loads(fixture_path.read_text())
 report=dict(kind='authenticated-completion010',status='RUNNING',conformance='NOT_ESTABLISHED',scope=fixture['scope'],fixture_sha256=digest(fixture_path),subjects={},scenarios=[],lifecycle=[],controls=[],raw='raw.jsonl',inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip())
 raw=(output/'raw.jsonl').open('w');
 def log(v):raw.write(json.dumps(v)+'\n');raw.flush()
 def save():(output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 save();unique={k:set() for k in ('ctx','nonce','enc','ephC')}
 try:
  for n,program in programs.items():
   repo=ROOT.parent/('sage' if n=='go' else 'rs-sage-core');revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip();assert revision==PINS[n],'unreviewed revision';assert not subprocess.check_output(['git','diff','HEAD','--'],cwd=repo),'changed core source'
   copy_path=repo/('pkg/agent/hpke/testdata/completion010.json' if n=='go' else 'tests/fixtures/completion010.json');assert digest(copy_path)==digest(fixture_path)
   report['subjects'][n]=dict(revision=revision,executable_sha256=digest(program))
  assert len(fixture['cases'])==36
  with tempfile.TemporaryDirectory() as directory:
   tmp=Path(directory)
   for sender,receiver in itertools.product(programs,repeat=2):
    for case in fixture['cases']:
     label=sender+'-to-'+receiver+'-'+case['id'];a=Actor(label+'-init','alice',tmp/(label+'-a'),programs[sender],log);b=Actor(label+'-resp','bob',tmp/(label+'-b'),programs[receiver],log)
     try:
      first=a.call('start',ttl=case.get('init_ttl',300));assert first['state']=='INIT_SENT';request=bytes.fromhex(first['wire_hex']);init=json.loads(decode(json.loads(request)['payload']))
      for k in unique:assert init[k] not in unique[k],'reused fresh contribution';unique[k].add(init[k])
      second=b.call('respond',wire_hex=request.hex(),ttl=case.get('response_ttl',300));assert second['state']=='RESPONSE_SENT';response=bytes.fromhex(second['wire_hex']);t,th,sid=independent(request,response);assert second['tuple']['th']==th and second['tuple']['sid']==sid
      if case.get('abandon'):a.call('pending-close')
      if case.get('endpoint_close'):a.call('endpoint-close')
      altered=changed(request,response,case.get('mutation',''));c={k:case[k] for k in ('mode','mono_ms','unix') if k in case}
      accepted=case['accept'];result=a.call('complete','ACCEPT' if accepted else 'REJECT',wire_hex=altered.hex(),**c)
      if accepted:assert result==dict(state='ESTABLISHED',tuple=second['tuple'])
      state=a.call('inspect');assert state==dict(pending_state='CLOSED',result_state='ESTABLISHED' if accepted else 'NONE')
      a.call('complete','REJECT',wire_hex=response.hex(),**c);b.call('dispatch','UNSUPPORTED')
      report['scenarios'].append(dict(id=label,status='PASS',independent_signatures=3,th=th,sid=sid));save()
     finally:
      try:a.close()
      finally:b.close()
    for mode in ('revoke-init','revoke-resp','revoke-kem','source-error','unrelated','expiry','closed'):
     label=f'{sender}-to-{receiver}-lifecycle-{mode}';a=Actor(label+'-init','alice',tmp/(label+'-a'),programs[sender],log);b=Actor(label+'-resp','bob',tmp/(label+'-b'),programs[receiver],log)
     try:
      request=a.call('start')['wire_hex'];reply=b.call('respond',wire_hex=request)['wire_hex'];b.call('respond','REJECT',wire_hex=request);a.call('complete',wire_hex=reply)
      c=dict(mode=mode) if mode not in ('expiry','closed') else {};expect='ACCEPT' if mode=='unrelated' else 'REJECT'
      if mode=='expiry':c.update(mono_ms=300000,unix=400)
      if mode=='closed':b.call('close')
      b.call('check',expect,**c);assert b.call('inspect')['result_state']==('RESPONSE_SENT' if mode=='unrelated' else 'CLOSED')
      if mode not in ('expiry','closed'):a.call('check',expect,**c);assert a.call('inspect')['result_state']==('ESTABLISHED' if mode=='unrelated' else 'CLOSED')
      report['lifecycle'].append(dict(id=label,status='PASS'));save()
     finally:
      try:a.close()
      finally:b.close()
    label=f'{sender}-to-{receiver}-key-expiry-during-commit';a=Actor(label+'-init','alice',tmp/(label+'-a'),programs[sender],log,101);b=Actor(label+'-resp','bob',tmp/(label+'-b'),programs[receiver],log,101)
    try:
     request=a.call('start')['wire_hex'];reply=b.call('respond',wire_hex=request)['wire_hex'];a.call('complete','REJECT',wire_hex=reply,mode='utc-delay');assert a.call('inspect')==dict(pending_state='CLOSED',result_state='NONE');report['lifecycle'].append(dict(id=label,status='PASS'));save()
    finally:
     try:a.close()
     finally:b.close()
   for name,program in programs.items():
    for index,q in enumerate([{},dict(id='x',action='start',mono_ms=0,unix=100,unexpected=True),dict(id='x',action='complete',mono_ms=0,unix=100),dict(id='x',action='start',mono_ms=0,unix=100,mode='arbitrary')]):
     p=subprocess.run([str(program),'alice',str(tmp/f'{name}-bad-{index}')],input=canonical(q)+b'\n',capture_output=True,timeout=15);log(dict(actor=f'{name}-bad-{index}',request=q,exit_code=p.returncode,stdout=p.stdout.decode(),stderr=p.stderr.decode()));assert p.returncode==2 and not p.stdout;report['controls'].append(f'{name}-{index}')
  report['status']='PASS'
 except Exception as error:report.update(status='FAIL',reason=str(error));raise
 finally:raw.close();report['raw_sha256']=digest(output/'raw.jsonl');save()
 print('144 completion scenarios, 32 lifecycle cases, 8 malformed controls; independent signatures and all four core combinations passed')
if __name__=='__main__':main()
