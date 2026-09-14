"""Public independent Guard fixtures. No SAGE runtime or policy implementation imported."""
import base64,copy,hashlib,json,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
ROOT=Path(__file__).resolve().parents[1];NOW=1700000000
ISSUER='did:sage:web:agents.example.com:alice';EXECUTOR='did:sage:web:agents.example.com:executor'
def sha(b):return hashlib.sha256(b).hexdigest()
def jcs(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def b64(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def uuid(n):return '00000000-0000-4000-8000-'+str(n).zfill(12)
SK=ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'public Guard fixture issuer').digest())
RK=ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'public Guard fixture executor').digest())
def pub(k):return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def sign(kind,obj):return {kind:copy.deepcopy(obj),'proof':b64((SK if kind=='intent' else RK).sign(('sage-execution-intent|0.10.0' if kind=='intent' else 'sage-tool-result|0.10.0').encode()+b'\0'+jcs(obj)))}
def capture(items):return b'sage-original|0.10.0\0'+len(items).to_bytes(4,'big')+b''.join(len(x).to_bytes(8,'big')+x for x in items)
ARTIFACTS=[dict(path='engine.bin',bytes_hex=b'public pinned evaluator'.hex()),dict(path='rules.json',bytes_hex=b'{"allow":["read"]}'.hex())]
MANIFEST=dict(version='0.10.0',files=[dict(path=a['path'],sha256=sha(bytes.fromhex(a['bytes_hex']))) for a in ARTIFACTS])
POLICY=dict(version='0.10.0',issuer=ISSUER,epoch=uuid(1),engine='fixture-evaluator/1',artifacts=MANIFEST)
def policy_digest(p):return sha(b'sage-policy|0.10.0\0'+jcs(p))
INTENT=dict(version='0.10.0',profile='sage-execution-guard',request_id=uuid(2),call_id=uuid(3),parent_call_id=None,original_digest=sha(capture([b'read public document'])),issuer=ISSUER,recipient=EXECUTOR,tool='read',arguments=dict(path='public.txt'),policy_digest=policy_digest(POLICY),manifest_digest=sha(jcs(MANIFEST)),created=NOW,expires=NOW+300,nonce=b64(bytes(range(16))),keyid=ISSUER+'#signing-1',alg='ed25519')
ENVELOPE=sign('intent',INTENT)
def result(status='completed',envelope=ENVELOPE):
 i=envelope['intent'];return sign('result',dict(version='0.10.0',request_id=i['request_id'],call_id=i['call_id'],issuer=EXECUTOR,recipient=ISSUER,created=NOW,expires=NOW+300,keyid=EXECUTOR+'#signing-1',alg='ed25519',intent_digest=sha(jcs(envelope)),status=status,output=dict(text='public output') if status=='completed' else {}))
SOURCES=[dict(id='guard-spec',kind='spec-derived',uri='sage-spec/profiles/agent-mcp-security.md',reference='EXEC-01..09; CST-01/02 closure. Exact test-only inputs and independent Python signatures, Node audits. No host isolation or real dispatch claim.')]
def generate(out):
 out.mkdir(parents=True,exist_ok=True);cases=[]
 def case(name,op,inp,ok=True,output=None,rules=('EXEC-03',)):
  cases.append(dict(id=name,operation=op,rule_ids=list(rules),source_ids=['guard-spec'],derivation='Independently authored protocol expectation; exact public test bytes, Python cryptography Ed25519/SHA256 and separate Node audit.',input=inp,expected=dict(verdict='ACCEPT' if ok else 'REJECT',output=(output if output is not None else dict(valid=True)) if ok else {})))
 for name,items in [('single',[b'ab']),('bundle',[b'a',b'b']),('space',[b'ab ']),('composed',['é'.encode()]),('decomposed',['é'.encode()]),('empty-item',[b'']),('count-max',[b'']*1024),('count-over',[b'']*1025),('bytes-max',[b'a'*(1<<20)]),('bytes-over',[b'a'*((1<<20)+1)])]:
  ok=len(items)<=1024 and sum(map(len,items))<=1<<20
  # Byte recipe is expanded by the trusted fixture boundary, not by model policy.
  inp=dict(items=[dict(hex=x.hex()) if len(x)<100 else dict(byte=97,length=len(x)) for x in items])
  case('original-'+name,'sage.guard.original.commit',inp,ok,dict(original_digest=sha(capture(items))),('EXEC-02',))
 case('manifest-valid','sage.guard.manifest.verify',dict(manifest=MANIFEST,artifacts=ARTIFACTS),output=dict(manifest_digest=sha(jcs(MANIFEST))),rules=('EXEC-06',))
 for name,path in [('parent','../engine.bin'),('dot','./engine.bin'),('empty','dir//engine.bin'),('absolute','/engine.bin'),('backslash','dir\\engine.bin'),('nul','engine\0.bin')]:
  m=copy.deepcopy(MANIFEST);m['files'][0]['path']=path;art=copy.deepcopy(ARTIFACTS);art[0]['path']=path
  case('manifest-'+name,'sage.guard.manifest.verify',dict(manifest=m,artifacts=art),False,rules=('EXEC-06',))
 for name,mut in [('duplicate',lambda m:m['files'].append(m['files'][0])),('unsorted',lambda m:m['files'].reverse()),('hash',lambda m:m['files'][0].update(sha256='00'*32))]:
  m=copy.deepcopy(MANIFEST);mut(m);art=copy.deepcopy(ARTIFACTS)
  if name=='duplicate':art.append(copy.deepcopy(art[0]))
  case('manifest-'+name,'sage.guard.manifest.verify',dict(manifest=m,artifacts=art),False,rules=('EXEC-06',))
 for n in (2044,2045):
  p=copy.deepcopy(POLICY);p['artifacts']['files']=[dict(path='file'+str(i).zfill(4),sha256='00'*32) for i in range(n)]
  case('policy-members-'+str(n),'sage.guard.policy.commit',dict(descriptor=p),n==2044,dict(policy_digest=policy_digest(p)),('EXEC-02',))
 for n in (1048576,1048577):
  prefix=b'{"data":"';suffix=b'"}';case('json-bytes-'+str(n),'sage.guard.json.bounds',dict(prefix_hex=prefix.hex(),repeat_byte=97,repeat_count=n-len(prefix)-len(suffix),suffix_hex=suffix.hex()),n==1048576,rules=('EXEC-03','EXEC-07'))
 for n in (32,33):
  raw=b'{"a":'*(n-1)+b'{}'+b'}'*(n-1);case('json-depth-'+str(n),'sage.guard.json.bounds',dict(prefix_hex=raw.hex(),repeat_byte=97,repeat_count=0,suffix_hex=''),n==32,rules=('EXEC-03','EXEC-07'))
 for n in (4096,4097):
  raw=jcs({'a'+str(i):0 for i in range(n)});case('json-members-'+str(n),'sage.guard.json.bounds',dict(prefix_hex=raw.hex(),repeat_byte=97,repeat_count=0,suffix_hex=''),n==4096,rules=('EXEC-03','EXEC-07'))
 for name,p,ok in [('valid',POLICY,True),('empty',dict(POLICY,artifacts=dict(version='0.10.0',files=[])),False),('version',dict(POLICY,version='0.9.0'),False),('epoch',dict(POLICY,epoch='not-a-uuid'),False),('engine',dict(POLICY,engine=''),False)]:case('policy-'+name,'sage.guard.policy.commit',dict(descriptor=p),ok,dict(policy_digest=policy_digest(p)),('EXEC-02',))
 # Frozen published CST-02 policy commitment example.
 example=dict(version='0.10.0',issuer='did:sage:web:agents.example.com:policy-example',epoch=uuid(1),engine='example-deny/1',artifacts=dict(version='0.10.0',files=[dict(path='policy.txt',sha256=sha(b'deny\n'))]))
 assert policy_digest(example)=='e70a2dfb87b9a2760e540a2ca96e16d55ec1fb346cfeba7515ed40ca5ab08bdb'
 case('policy-published-example','sage.guard.policy.commit',dict(descriptor=example),output=dict(policy_digest=policy_digest(example)),rules=('EXEC-02',))
 def intentcase(name,env=ENVELOPE,ok=True,**changes):
  inp=dict(envelope_hex=jcs(env).hex(),now=NOW,clock_trusted=True,public_key_hex=pub(SK),active_key=True,expected_issuer=ISSUER,expected_recipient=EXECUTOR,approved_policy=POLICY,approved_manifest=MANIFEST,original_digest=INTENT['original_digest'],tool_schema=dict(tool='read',required=['path'],properties=dict(path='string')),policy_allow=True);inp.update(changes);case('intent-'+name,'sage.guard.intent.verify',inp,ok)
 intentcase('valid');intentcase('last-second',now=NOW+299);intentcase('expiry',ok=False,now=NOW+300);intentcase('early-limit',now=NOW-30);intentcase('too-early',ok=False,now=NOW-31)
 for name,change in [('clock',dict(clock_trusted=False)),('inactive-key',dict(active_key=False)),('recipient',dict(expected_recipient=ISSUER)),('original',dict(original_digest='00'*32)),('policy-deny',dict(policy_allow=False))]:intentcase(name,ok=False,**change)
 for name,change in [('version',dict(version='0.9.0')),('profile',dict(profile='other')),('tool',dict(tool='delete')),('recursive',dict(tool='sage_secure_call')),('arguments-extra',dict(arguments=dict(path='public.txt',admin=True))),('arguments-missing',dict(arguments={})),('arguments-type',dict(arguments=dict(path=4))),('lifetime',dict(expires=NOW+301)),('policy-self-approved',dict(policy_digest='11'*32)),('manifest-self-approved',dict(manifest_digest='22'*32)),('key-binding',dict(keyid=EXECUTOR+'#signing-1')),('parent-invalid',dict(parent_call_id='bad')),('unknown-field',dict(extra=True)),('null-arguments',dict(arguments=None)),('array-arguments',dict(arguments=[]))]:
  i=copy.deepcopy(INTENT);i.update(change);intentcase(name,sign('intent',i),False)
 tamper=copy.deepcopy(ENVELOPE);tamper['intent']['arguments']['path']='private.txt';intentcase('tampered',tamper,False)
 for status in ('pending','completed','rejected','unknown'):
  env=result(status)
  def rescase(name,e=env,ok=True,**changes):
   inp=dict(envelope_hex=jcs(e).hex(),intent_envelope=ENVELOPE,now=NOW,public_key_hex=pub(RK),active_key=True,clock_trusted=True,outstanding=True);inp.update(changes);case('result-'+status+'-'+name,'sage.guard.result.verify',inp,ok,rules=('EXEC-07',))
  rescase('valid');rescase('unsolicited',ok=False,outstanding=False)
  if status=='completed':
   later=copy.deepcopy(env['result']);later.update(created=NOW+301,expires=NOW+601);rescase('accepted-invocation-late-result',sign('result',later),now=NOW+301)
   rescase('expired',ok=False,now=NOW+300);rescase('revoked',ok=False,active_key=False)
  altered=copy.deepcopy(env['result']);altered['intent_digest']='00'*32;rescase('wrong-intent',sign('result',altered),False)
  if status!='completed':
   altered=copy.deepcopy(env['result']);altered['output']=dict(instruction='execute');rescase('output',sign('result',altered),False)
  for label,extra,ok in [('valid',{},True),('error-flag',dict(isError=status=='completed'),False),('extra-block',dict(extra_block=True),False),('text-mismatch',dict(text='{}'),False)]:
   inp=dict(structured=env,text=jcs(env).decode(),isError=status!='completed',extra_block=False);inp.update(extra);case('mcp-'+status+'-'+label,'sage.guard.mcp.result',inp,ok,rules=('EXEC-08',))
 for name,env,key,kind in [('intent',ENVELOPE,SK,'intent'),('result',result(),RK,'result')]:
  prefix=b'sage-execution-intent|0.10.0\0' if kind=='intent' else b'sage-tool-result|0.10.0\0'
  for label,msg,ok in [('valid',prefix+jcs(env[kind]),True),('domain',b'wrong-domain\0'+jcs(env[kind]),False)]:case(name+'-signature-'+label,'signature.verify',dict(algorithm='ed25519',public_key_hex=pub(key),message_hex=msg.hex(),signature_hex=base64.urlsafe_b64decode(env['proof']+'==').hex()),ok,rules=('EXEC-03' if kind=='intent' else 'EXEC-07',))
 for name,obj in [('manifest',MANIFEST),('policy',POLICY),('intent',ENVELOPE),('result',result())]:case('jcs-'+name,'jcs.canonicalize',dict(document_hex=json.dumps(obj).encode().hex()),output=dict(canonical_hex=jcs(obj).hex()),rules=('EXEC-02','EXEC-03','EXEC-06','EXEC-07'))
 root=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',id='sage-guard-records-0.10.0',sources=SOURCES,cases=cases)
 (out/'guard-records.json').write_text(json.dumps(root,indent=2)+'\n')
 from guard_scenarios import scenarios
 ss=scenarios(ENVELOPE,POLICY,MANIFEST,ARTIFACTS,pub(SK),pub(RK),result,SOURCES,sign)
 folder=out/'guard-scenarios';folder.mkdir(exist_ok=True);manifest=dict(schema_version=1,protocol_version='0.10.0',records_sha256=sha((out/'guard-records.json').read_bytes()),scenarios=[])
 for s in ss:
  f=folder/(s['id']+'.json');f.write_text(json.dumps(s,indent=2)+'\n');manifest['scenarios'].append(dict(id=s['id'],file=f.name,sha256=sha(f.read_bytes()),rule_ids=['EXEC-02','EXEC-04','EXEC-05','EXEC-06','EXEC-07','EXEC-08']))
 (out/'guard-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 links=[]
 for group,files in {'CST-01':['guard-scenarios/guard-pending-completed.json','guard-scenarios/guard-client-pending-terminal.json','guard-scenarios/guard-client-terminal-conflict.json','guard-scenarios/guard-crash-executing.json','guard-scenarios/guard-race-reject-reserve.json'], 'CST-02':['guard-records.json','guard-scenarios/guard-scope-recovery.json','guard-scenarios/guard-race-retire-first.json'], 'CST-03':['session-records.json'], 'CST-04':['session-scenarios/session-pinned-did.json','session-scenarios/session-pinned-kid-active-alternative.json'], 'CST-05':['session-scenarios/session-provisional-race.json','session-scenarios/session-provisional-application-reject.json','session-scenarios/session-provisional-commit-deadline.json']}.items():
  for name in files:
   path=out/name if name.startswith('guard-') else ROOT/'vectors/0.10.0'/name
   raw=path.read_bytes();links.append(dict(group=group,file=name,id=json.loads(raw)['id'],sha256=sha(raw)))
 (out/'guard-closure-links.json').write_text(json.dumps(dict(scope='Fixture readiness links only. Existing session evidence remains separate; no closure group is promoted to runtime conformance.',links=links),indent=2)+'\n')
 print(len(cases),'cases',len(ss),'scenarios',sum(len(s['steps']) for s in ss),'steps')
if __name__=='__main__':generate(Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'vectors/0.10.0')
