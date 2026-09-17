"""Bound HTTP handshakes and safe real TLS exchanges over loopback only."""
import argparse,copy,hashlib,itertools,json,ssl,subprocess,tempfile,threading
from pathlib import Path
from test_completion010 import Actor,ROOT,canonical,digest,independent,changed
from test_http_session010 import audit,mutate,body,b64,resign,field,headers
from test_record010_adapters import PINS
from http_tls010 import parse,render,certificates,listener,exchange
TARGET='https://localhost:8443/messages'

def wire(actor,action,**kw):return bytes.fromhex(actor.call(action,**kw)['wire_hex'])
def configure(a,b,target):a.call('http-endpoint-bind',target=target);b.call('http-endpoint-bind',target=target)
def observe(a,handshakes,records,session):
 v=a.call('http-inspect');assert (v['handshakes'],v['records'],v['session'])==(handshakes,records,session),v;return v

def scenario(a,b,kind):
 configure(a,b,TARGET);q=wire(a,'http-start');qm=parse(q,TARGET);audit(qm,1)
 if kind=='bare-bypass':a.call('start','REJECT');b.call('respond','REJECT',wire_hex=body(qm).hex())
 if kind.startswith('request-'):
  name={'request-signature':'signature','request-digest':'body-digest','request-duplicate':'duplicate-signature'}.get(kind,kind)
  bad=mutate(qm,name,1);b.call('http-respond-raw','REJECT',wire_hex=render(bad).hex());observe(b,0,0,'NONE')
 r=wire(b,'http-respond-raw',wire_hex=q.hex());rm=parse(r,TARGET,True);audit(rm,2,qm);independent(body(qm),body(rm));observe(b,1,0,'RESPONSE_SENT')
 if kind=='duplicate-initiation':b.call('http-respond-raw','REJECT',wire_hex=q.hex());observe(b,1,0,'RESPONSE_SENT')
 if kind=='bare-bypass':a.call('complete','REJECT',wire_hex=body(rm).hex())
 if kind=='first-record':b.call('http-record-seal-raw','REJECT',wire_hex='')
 reject=False;controls={};expected_reservations=0
 if kind in ('response-signature','response-status','response-digest','response-request-signature'):
  name={'response-signature':'signature','response-status':'response-status-tamper','response-digest':'body-digest','response-request-signature':'response-request-signature'}[kind]
  r=render(mutate(rm,name,2,qm));reject=True
 elif kind=='inner-completion':rm['body']=b64(changed(body(qm),body(rm),'inner-signature'));resign(rm,2,qm,True);r=render(rm);reject=True
 elif kind in ('revoke-resp','store-delay','store-error'):controls['mode']=kind;reject=True;expected_reservations=int(kind=='store-delay')
 elif kind=='expired':controls['unix']=400;reject=True
 elif kind=='closed-pending':a.call('pending-close');reject=True
 a.call('http-complete-raw','REJECT' if reject else 'ACCEPT',wire_hex=r.hex(),**controls)
 if reject:assert observe(a,expected_reservations,0,'NONE')['pending']=='CLOSED';return
 observe(a,1,0,'ESTABLISHED');a.call('http-complete-raw','REJECT',wire_hex=r.hex());observe(a,1,0,'ESTABLISHED')
 a.call('record-seal','REJECT',wire_hex='');request=wire(a,'http-record-seal-raw',wire_hex=b'request'.hex());qm=parse(request,TARGET);audit(qm,1)
 b.call('record-open','REJECT',wire_hex=body(qm).hex());assert b.call('http-record-open-raw',wire_hex=request.hex())['plaintext_hex']==b'request'.hex();observe(b,1,1,'ESTABLISHED')
 code='operation_failed' if kind=='error-response' else '';message_id=json.loads(body(qm))['id'];r=wire(b,'http-response-seal-raw',message_id=message_id,success=not code,error=code,wire_hex=b'result'.hex());audit(parse(r,TARGET,True),2,qm)
 result=a.call('http-response-open-raw',wire_hex=r.hex());assert result==dict(message_id=message_id,success=not code,error=code,plaintext_hex=b'result'.hex());observe(a,1,1,'ESTABLISHED')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('go','rust','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--development',action='store_true');args=p.parse_args();out=args.output.resolve()
 if ROOT/'docs/evidence' in (out,*out.parents):p.error('preserve historical evidence')
 out.mkdir(parents=True,exist_ok=False);raw=(out/'raw.jsonl').open('w');lock=threading.Lock()
 def log(v):
  with lock:raw.write(json.dumps(v)+'\n');raw.flush()
 fixture=ROOT/'vectors/0.10.0/http-handshake010.json';f=json.loads(fixture.read_text());programs={n:getattr(args,n).resolve() for n in PINS}
 report=dict(kind='http-handshake010',status='RUNNING',conformance='NOT_ESTABLISHED',development=args.development,scope=f['scope'],fixture_sha256=digest(fixture),subjects={},scenarios=[],tls=[],raw='raw.jsonl',inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),tls_runtime=ssl.OPENSSL_VERSION)
 def save():(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 save()
 try:
  for name,program in programs.items():
   repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip();diff=subprocess.check_output(['git','diff','HEAD','--'],cwd=repo)
   if not args.development:assert rev==PINS[name] and not diff
   assert digest(repo/('pkg/agent/hpke/testdata/http-handshake010.json' if name=='go' else 'tests/fixtures/http-handshake010.json'))==digest(fixture)
   report['subjects'][name]=dict(revision=rev,executable_sha256=digest(program),tracked_diff_sha256=hashlib.sha256(diff).hexdigest())
  assert len(f['cases'])==22 and len(f['framing'])==24
  with tempfile.TemporaryDirectory() as directory:
   tmp=Path(directory);certdir=tmp/'certs';certdir.mkdir();server_context,client_context,cert_hash=certificates(certdir);report['test_certificate_sha256']=cert_hash
   for sender,receiver in itertools.product(programs,repeat=2):
    for kind in f['cases']:
     label=f'{sender}-to-{receiver}-{kind}';a=Actor(label+'-a','alice',tmp/(label+'-a'),programs[sender],log);b=Actor(label+'-b','bob',tmp/(label+'-b'),programs[receiver],log)
     try:scenario(a,b,kind);report['scenarios'].append(dict(id=label,status='PASS'));save()
     finally:
      try:a.close()
      finally:b.close()
    for kind in ('success','application-error','untrusted-ca','wrong-hostname'):
     label=f'{sender}-to-{receiver}-tls-{kind}';sock=listener();target=f'https://localhost:{sock.getsockname()[1]}/messages';a=Actor(label+'-a','alice',tmp/(label+'-a'),programs[sender],log);b=Actor(label+'-b','bob',tmp/(label+'-b'),programs[receiver],log)
     try:
      configure(a,b,target);q=wire(a,'http-start');qm=parse(q,target);audit(qm,1)
      if kind in ('untrusted-ca','wrong-hostname'):
       client=ssl.create_default_context() if kind=='untrusted-ca' else client_context
       _,evidence=exchange(sock,server_context,client,q,lambda _:(_ for _ in ()).throw(AssertionError('untrusted dispatch')),True,'wrong.example' if kind=='wrong-hostname' else 'localhost');observe(b,0,0,'NONE');report['tls'].append(dict(id=label,status='PASS',evidence=evidence));save();continue
      r,evidence=exchange(sock,server_context,client_context,q,lambda data:wire(b,'http-respond-raw',wire_hex=data.hex()));rm=parse(r,target,True);audit(rm,2,qm);independent(body(qm),body(rm));a.call('http-complete-raw',wire_hex=r.hex());observe(b,1,0,'RESPONSE_SENT');observe(a,1,0,'ESTABLISHED')
      # Keep the same configured endpoint while opening a fresh one-message connection.

      request=wire(a,'http-record-seal-raw',wire_hex=b'TLS request'.hex());request_message=parse(request,target);audit(request_message,1);message_id=json.loads(body(request_message))['id'];code='operation_failed' if kind=='application-error' else ''
      def handle(data):
       assert b.call('http-record-open-raw',wire_hex=data.hex())['plaintext_hex']==b'TLS request'.hex()
       return wire(b,'http-response-seal-raw',message_id=message_id,success=not code,error=code,wire_hex=b'TLS result'.hex())
      response,record_evidence=exchange(sock,server_context,client_context,request,handle);audit(parse(response,target,True),2,request_message);result=a.call('http-response-open-raw',wire_hex=response.hex());assert result==dict(message_id=message_id,success=not code,error=code,plaintext_hex=b'TLS result'.hex());observe(b,1,1,'ESTABLISHED');observe(a,1,1,'ESTABLISHED')
      report['tls'].append(dict(id=label,status='PASS',handshake=evidence,record=record_evidence));save()
     finally:
      sock.close()
      try:a.close()
      finally:b.close()
  report['status']='PASS'
 except Exception as exc:report.update(status='FAIL',reason=str(exc));raise
 finally:raw.close();report['raw_sha256']=digest(out/'raw.jsonl');save()
 print('88 HTTP handshake process scenarios and 16 loopback TLS scenarios passed')
if __name__=='__main__':main()
