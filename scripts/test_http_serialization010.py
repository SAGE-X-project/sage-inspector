"""Bounded profile serialization checks through actual core CLI processes."""
import argparse,copy,hashlib,itertools,json,re,subprocess,tempfile
from pathlib import Path
from test_completion010 import Actor,ROOT,digest
from test_http_handshake010 import wire,configure,observe
from test_http_session010 import headers,field,resign,signature_base,audit
from http_tls010 import parse,render
from test_record010_adapters import PINS

def instantiate(template,actual):
 values=dict(re.findall(r';(keyid|nonce)="([^"]*)"',actual))
 return re.sub(r'(; *)(keyid|nonce)="[^"]*"',lambda m:m[1]+m[2]+'="'+values[m[2]]+'"',template)

def variation(message,case,key,request=None):
 m=copy.deepcopy(message);actual=headers(m)['signature-input'];base_hash=None
 if case['accept']:
  field(m,'signature-input',instantiate(case['canonical'],actual));resign(m,key,request)
  base_hash=hashlib.sha256(signature_base(m,request)).hexdigest()
 field(m,'signature-input',instantiate(case['input'],actual))
 return m,base_hash

def exchange_case(a,b,case,target):
 configure(a,b,target);q=wire(a,'http-start');qm=parse(q,target);base_hash=None
 if case and not case['response']:
  qm,base_hash=variation(qm,case,1);q=render(qm)
  if not case['accept']:
   b.call('http-respond-raw','REJECT',wire_hex=q.hex());observe(b,0,0,'NONE');return base_hash
 r=wire(b,'http-respond-raw',wire_hex=q.hex());rm=parse(r,target,True)
 if case and case['id']=='request-parameter-order':
  # Re-signing after emission changes the retained request signature. The
  # receiver accepts the new valid signature, but the original sender must
  # reject the response bound to those changed request bytes.
  audit(rm,2,qm);observe(b,1,0,'RESPONSE_SENT')
  a.call('http-complete-raw','REJECT',wire_hex=r.hex());assert observe(a,0,0,'NONE')['pending']=='CLOSED';return base_hash
 if case and case['response']:
  rm,base_hash=variation(rm,case,2,qm);r=render(rm)
  if not case['accept']:
   a.call('http-complete-raw','REJECT',wire_hex=r.hex());assert observe(a,0,0,'NONE')['pending']=='CLOSED';return base_hash
 a.call('http-complete-raw',wire_hex=r.hex());observe(a,1,0,'ESTABLISHED');observe(b,1,0,'RESPONSE_SENT')
 # First encrypted record proves the negotiated session remains usable.
 q=wire(a,'http-record-seal-raw',wire_hex=b'serialization'.hex());m=parse(q,target)
 assert m['target']==target and m['authority']==target.split('/')[2]
 assert b.call('http-record-open-raw',wire_hex=q.hex())['plaintext_hex']==b'serialization'.hex();observe(b,1,1,'ESTABLISHED')
 return base_hash or hashlib.sha256(signature_base(m)).hexdigest()

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('go','rust','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--development',action='store_true');args=p.parse_args();out=args.output.resolve()
 if ROOT/'docs/evidence' in (out,*out.parents):p.error('preserve historical evidence')
 out.mkdir(parents=True,exist_ok=False);raw=(out/'raw.jsonl').open('w')
 def log(v):raw.write(json.dumps(v)+'\n');raw.flush()
 fixture=ROOT/'vectors/0.10.0/http-serialization010.json';f=json.loads(fixture.read_text());programs={n:getattr(args,n).resolve() for n in PINS}
 report=dict(kind='http-serialization010',status='RUNNING',conformance='NOT_ESTABLISHED',development=args.development,fixture_sha256=digest(fixture),rfc_example_sha256=digest(ROOT/'vectors/0.10.0/rfc9421-ed25519.json'),subjects={},scenarios=[],raw='raw.jsonl',inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip())
 def save():(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 save()
 try:
  for name,program in programs.items():
   repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip();diff=subprocess.check_output(['git','diff','HEAD','--'],cwd=repo)
   if not args.development:assert rev==PINS[name] and not diff
   assert digest(repo/('pkg/agent/hpke/testdata/http-serialization010.json' if name=='go' else 'tests/fixtures/http-serialization010.json'))==digest(fixture)
   report['subjects'][name]=dict(revision=rev,executable_sha256=digest(program),tracked_diff_sha256=hashlib.sha256(diff).hexdigest())
  with tempfile.TemporaryDirectory() as directory:
   tmp=Path(directory)
   for sender,receiver in itertools.product(programs,repeat=2):
    cases=[(c['id'],c,'https://agent.example/messages',True) for c in f['structured_fields']]+[('uri-'+str(i),None,c['target'],c['accept']) for i,c in enumerate(f['uris'])]
    for name,case,target,admit in cases:
     label=sender+'-to-'+receiver+'-'+name;a=Actor(label+'-a','alice',tmp/(label+'-a'),programs[sender],log);b=Actor(label+'-b','bob',tmp/(label+'-b'),programs[receiver],log)
     try:
      if not admit:
       a.call('http-endpoint-bind','REJECT',target=target);b.call('http-endpoint-bind','REJECT',target=target);observe(a,0,0,'NONE');observe(b,0,0,'NONE');base_hash=None
      else:base_hash=exchange_case(a,b,case,target)
      report['scenarios'].append(dict(id=label,status='PASS',base_sha256=base_hash));save()
     finally:
      try:a.close()
      finally:b.close()
  report['status']='PASS'
 except Exception as exc:report.update(status='FAIL',reason=str(exc));raise
 finally:raw.close();report['raw_sha256']=digest(out/'raw.jsonl');save()
 print(str(len(report['scenarios']))+' serialization and URI process scenarios passed')
if __name__=='__main__':main()
