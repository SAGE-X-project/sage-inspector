"""Safe local core processes: HTTP signatures plus one session acceptance."""
import argparse,base64,copy,hashlib,itertools,json,subprocess,tempfile
from pathlib import Path
from test_completion010 import Actor,ROOT,canonical,sign,verify,independent,digest
from test_record010_adapters import PINS

def b64(b):return base64.b64encode(b).decode()
def body(m):return base64.b64decode(m['body'],validate=True)
def headers(m):return {k.lower():v for k,v in m['headers']}
def field(m,k,v):
 for p in m['headers']:
  if p[0].lower()==k:p[1]=v;return
 m['headers'].append([k,v])
def content_digest(m):return 'sha-256=:'+b64(hashlib.sha256(body(m)).digest())+':'
def signature_base(m,q=None):
 h=headers(m);lines=[]
 if q is None:lines=[('"@method"',m['method']),('"@target-uri"',m['target']),('"@authority"',m['authority'])]
 else:
  original=headers(q);lines=[('"@status"',str(m['status']))]
  for k,v in [('"@method";req',q['method']),('"@target-uri";req',q['target']),('"@authority";req',q['authority']),('"content-digest";req',original['content-digest']),('"signature";req',original['signature']),('"x-sage-version";req',original['x-sage-version'])]:lines.append((k,v))
 for k in ('content-type','content-digest','x-sage-did','x-sage-version'):lines.append(('"'+k+'"',h[k]))
 lines.append(('"@signature-params"',h['signature-input'][5:]))
 return '\n'.join(k+': '+v for k,v in lines).encode()
def resign(m,key,q=None,update_digest=False):
 if update_digest:field(m,'content-digest',content_digest(m))
 field(m,'signature','sig1=:'+b64(sign(signature_base(m,q),key))+':')
def audit(m,key,q=None):
 h=headers(m);assert h['content-digest']==content_digest(m)
 sig=base64.b64decode(h['signature'][6:-1],validate=True);verify(signature_base(m,q),sig,key)
 w=json.loads(body(m));signature=base64.urlsafe_b64decode(w.pop('signature')+'==')
 verify((b'sage-wire-request|0.10.0\n' if q is None else b'sage-wire-response|0.10.0\n')+canonical(w),signature,key)
 if q is not None:
  original=json.loads(body(q));assert w['message_id']==original['id']
  expected=base64.urlsafe_b64encode(hashlib.sha256(canonical(original)).digest()).decode().rstrip('=');assert w['request_hash']==expected
 return hashlib.sha256(signature_base(m,q)).hexdigest()
def mutate(m,kind,key,q=None):
 m=copy.deepcopy(m);h=headers(m)
 if kind=='response-status-tamper':m['status']=201;return m
 if kind in ('request-method','request-target','request-authority','response-status'):
  f,v={'request-method':('method','GET'),'request-target':('target',m['target']+'?other=1'),'request-authority':('authority','other.example'),'response-status':('status',204)}[kind];m[f]=v
 elif kind=='body-digest':m['body']=b64(body(m)+b' ');return m
 elif kind.startswith('duplicate-') and kind!='duplicate-parameter':
  k={'duplicate-signature':'signature','duplicate-input':'signature-input','duplicate-digest':'content-digest','duplicate-type':'content-type','duplicate-sage':'x-sage-did'}[kind];m['headers'].append([k.upper(),h[k]]);return m
 elif kind in ('signature','multiple-signatures','noncanonical-base64'):
  field(m,'signature',{'signature':'sig1=:'+b64(bytes(64))+':','multiple-signatures':h['signature']+', '+h['signature'],'noncanonical-base64':h['signature'].replace('=:',':')}[kind]);return m
 elif kind in ('content-type','content-encoding','transfer-encoding','trailer','content-length','header-control','version','did','projection','metadata'):
  k,v={'content-type':('content-type','application/json; charset=utf-8'),'content-encoding':('content-encoding','identity'),'transfer-encoding':('transfer-encoding','chunked'),'trailer':('trailer','signature'),'content-length':('content-length','1'),'header-control':('extra','a\nb'),'version':('x-sage-version','1.0'),'did':('x-sage-did','did:sage:web:agent.example:other'),'projection':('x-sage-context-id','other'),'metadata':('x-sage-meta-key','value')}[kind];field(m,k,v)
 elif kind in ('unknown-parameter','duplicate-parameter','wrong-tag','wrong-keyid','wrong-nonce','wrong-created','wrong-alg','coverage','reordered-parameters'):
  v=h['signature-input']
  if kind=='unknown-parameter':v+=';extra=1'
  elif kind=='duplicate-parameter':v+=';tag="sage-0.10.0"'
  elif kind=='reordered-parameters':prefix,tail=v.split(');',1);v=prefix+');'+';'.join(reversed(tail.split(';')))
  else:
   old,new={'wrong-tag':('sage-0.10.0','sage-1.0'),'wrong-keyid':('#signing-1','#other'),'wrong-nonce':(';nonce="',';nonce="A'),'wrong-created':(';created=100',';created=101'),'wrong-alg':('ed25519','rsa-pss-sha512'),'coverage':('"@method"','"@path"')}[kind];v=v.replace(old,new)
  field(m,'signature-input',v)
 elif kind=='inner-signature':
  w=json.loads(body(m));w['signature']='A'*86;m['body']=b64(canonical(w));resign(m,key,q,True);return m
 elif kind=='response-request-signature':q=copy.deepcopy(q);field(q,'signature',headers(q)['signature']+'wrong')
 resign(m,key,q);return m

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for n in ('go','rust','output'):parser.add_argument('--'+n,type=Path,required=True)
 parser.add_argument('--development',action='store_true',help='Record uncommitted development evidence without asserting pinned subjects')
 args=parser.parse_args();out=args.output.resolve()
 if ROOT/'docs/evidence' in (out,*out.parents):parser.error('preserve historical evidence')
 out.mkdir(parents=True,exist_ok=False);raw=(out/'raw.jsonl').open('w')
 def log(v):raw.write(json.dumps(v)+'\n');raw.flush()
 fixture=ROOT/'vectors/0.10.0/http-session010.json';f=json.loads(fixture.read_text());programs={n:getattr(args,n).resolve() for n in PINS}
 report=dict(kind='http-session010',status='RUNNING',conformance='NOT_ESTABLISHED',development=args.development,scope=f['scope'],fixture_sha256=digest(fixture),subjects={},scenarios=[],raw='raw.jsonl',inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip())
 def save():(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 save()
 try:
  for name,program in programs.items():
   repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip();diff=subprocess.check_output(['git','diff','HEAD','--'],cwd=repo)
   if not args.development:assert rev==PINS[name] and not diff
   p=repo/('pkg/agent/hpke/testdata/http-session010.json' if name=='go' else 'tests/fixtures/http-session010.json');assert digest(p)==digest(fixture)
   report['subjects'][name]=dict(revision=rev,executable_sha256=digest(program),tracked_diff_sha256=hashlib.sha256(diff).hexdigest())
  assert len(f['cases'])==45
  with tempfile.TemporaryDirectory() as directory:
   tmp=Path(directory)
   for sender,receiver in itertools.product(programs,repeat=2):
    for kind in f['cases']:
     label=f'{sender}-to-{receiver}-{kind}';alice=Actor(label+'-a','alice',tmp/(label+'-a'),programs[sender],log);bob=Actor(label+'-b','bob',tmp/(label+'-b'),programs[receiver],log)
     try:
      q=alice.call('start')['wire_hex'];r=bob.call('respond',wire_hex=q)['wire_hex'];alice.call('complete',wire_hex=r);independent(bytes.fromhex(q),bytes.fromhex(r))
      alice.call('http-bind');bob.call('http-bind');a,b,key=alice,bob,2
      def seal(actor,action,**kw):return json.loads(bytes.fromhex(actor.call(action,**kw)['wire_hex']))
      def open_message(actor,action,m,expected='ACCEPT',**kw):return actor.call(action,expected,wire_hex=canonical(m).hex(),**kw)
      request=seal(a,'http-request-seal',wire_hex=b'request'.hex());req_hash=audit(request,1)
      invalid=kind.startswith(('request-','duplicate-','wrong-','content-')) or kind in ('body-digest','header-control','unknown-parameter','transfer-encoding','trailer','version','did','projection','metadata','signature','multiple-signatures','noncanonical-base64','coverage')
      if invalid:
       open_message(b,'http-request-open',mutate(request,kind,1),'REJECT');assert b.call('record-inspect')==dict(state='RESPONSE_SENT',reservations=0)
      if kind=='bare-bypass':b.call('record-open','REJECT',wire_hex=body(request).hex());a.call('record-seal','REJECT',wire_hex='')
      assert open_message(b,'http-request-open',request)['plaintext_hex']==b'request'.hex();assert b.call('record-inspect')==dict(state='ESTABLISHED',reservations=1)
      open_message(b,'http-request-open',request,'REJECT')
      if kind=='reverse':a,b,key=b,a,1;request=seal(a,'http-request-seal',wire_hex=b'reverse'.hex());req_hash=audit(request,2);open_message(b,'http-request-open',request)
      message_id=json.loads(body(request))['id'];data=b'' if kind=='empty' else b'result';code='policy_denied' if kind=='error' else ''
      control=dict(message_id=message_id,success=not code,error=code,wire_hex=data.hex())
      response=seal(b,'http-response-seal',**control);resp_hash=audit(response,key,request);b.call('http-response-seal','REJECT',**control)
      before=a.call('record-inspect')['reservations']
      if kind in ('response-status','response-status-tamper','response-request-signature','inner-signature'):
       open_message(a,'http-response-open',mutate(response,kind,key,request),'REJECT');assert a.call('record-inspect')['reservations']==before
      if kind=='bare-bypass':a.call('response-open','REJECT',wire_hex=body(response).hex());b.call('response-seal','REJECT',**control)
      if kind=='reordered-parameters':response=mutate(response,kind,key,request);resp_hash=audit(response,key,request)
      if kind in ('store-error','store-delay','revoke-resp','expired'):
       mode={'unix':400} if kind=='expired' else {'mode':kind}
       open_message(a,'http-response-open',response,'REJECT',**mode);assert a.call('record-inspect')['reservations']==before
       if kind!='store-error':
        if kind!='expired':assert a.call('record-inspect')['state']=='CLOSED'
        report['scenarios'].append(dict(id=label,status='PASS',request_base_sha256=req_hash,response_base_sha256=resp_hash));save();continue
      expected=dict(message_id=message_id,success=not code,error=code,plaintext_hex=data.hex())
      assert open_message(a,'http-response-open',response)==expected;assert a.call('record-inspect')['reservations']==before+1
      open_message(a,'http-response-open',response,'REJECT');assert a.call('record-inspect')['reservations']==before+1
      report['scenarios'].append(dict(id=label,status='PASS',request_base_sha256=req_hash,response_base_sha256=resp_hash));save()
     finally:
      try:alice.close()
      finally:bob.close()
  report['status']='PASS'
 except Exception as e:report.update(status='FAIL',reason=str(e));raise
 finally:raw.close();report['raw_sha256']=digest(out/'raw.jsonl');save()
 print('180 HTTP session scenarios passed across all four core combinations')
if __name__=='__main__':main()
