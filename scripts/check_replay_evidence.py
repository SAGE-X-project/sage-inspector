"""Validate archived stateful cross-core replay evidence without replaying a core."""
import hashlib,json
from pathlib import Path
from integrate_evidence import decode,require,same
ROOT=Path(__file__).resolve().parents[1]

def sha(raw):return hashlib.sha256(raw).hexdigest()

def request(step,operation):
 q=step['request']
 require(q['schema_version']==1 and q['protocol_version']=='0.10.0' and q['profile']=='primitive-foundation' and q['case_id']==step['id'] and q['operation']==operation,'request identity')
 require(sha(json.dumps(q,separators=(',',':')).encode())==step['request_sha256'],'request hash')
 require(step['expected_verdict']=='ACCEPT','changed transport expectation')
 if step['status']=='PASS':
  a=step['actual'];require(a['schema_version']==1 and a['case_id']==step['id'] and a['verdict']=='ACCEPT','false batch PASS')
 if step['status']=='UNSUPPORTED':
  a=step['actual'];require(a['case_id']==step['id'] and a['verdict']=='UNSUPPORTED','false unsupported')
 if step['status']=='FAIL':require(step.get('reason'),'failure without reason')
 require(step['status'] in ('PASS','FAIL','UNSUPPORTED'),'invalid executed status')
 return q['input']

def validate(report):
 require(report['schema_version']==1 and report['protocol_version']=='0.10.0' and report['conformance']=='NOT_ESTABLISHED','replay identity')
 require(report['created'] and report['environment'],'missing execution environment')
 subjects={s['name']:s for s in report['subjects']}
 require(set(subjects)=={'sage-go','sage-rust'} and len(report['subjects'])==2,'core identities')
 require(len({s['executable_sha256'] for s in subjects.values()})==2,'distinct executable identities')
 expected_keys={(a,b,d) for a,b in [('sage-go','sage-rust'),('sage-rust','sage-go')] for d in ('c2s','s2c')}
 counts=dict.fromkeys(('PASS','FAIL','UNSUPPORTED','NOT_RUN'),0);seen=set();status='PASS'
 expected=[]
 for p in ('61','reject','reject','62','64','63','reject','close','reject'):
  expected.append(dict(verdict='REJECT' if p=='reject' else 'ACCEPT',output={} if p in ('reject','close') else {'plaintext_hex':p}))
 for t in report['trials']:
  key=(t['sender'],t['receiver'],t['direction']);require(key in expected_keys and key not in seen,'exchange membership');seen.add(key)
  ident=key[0]+'-to-'+key[1]+'-'+key[2];require(t['id']==ident,'trial identity')
  require(same(t['expected_actions'],expected),'changed replay expectations')
  require(t['production']['id']==ident+'-produce-sequence' and t['reception']['id']==ident+'-receive-sequence' and t['fresh_record_control']['id']==ident+'-fresh-record-control','step identity')
  controls=dict(seed_hex='01'*32,sid='inspector-replay-exchange',direction=key[2],caller_aad_hex='73616765',messages_hex=['61','62','63','64','65'])
  require(same(request(t['production'],'legacy.session.export-sequence'),controls),'changed producer controls')
  action_status=['NOT_RUN']*9
  if t['production']['status']=='PASS':
   records=t['production']['actual']['output']['records_hex']
   require(len(records)==5 and len(set(records))==5,'producer membership')
   for r in records:require(0<len(bytes.fromhex(r))<=2048 and bytes.fromhex(r).hex()==r,'invalid record')
   corrupted=bytes.fromhex(records[1]);corrupted=(corrupted[:-1]+bytes([corrupted[-1]^1])).hex()
   actions=[{'kind':'close'} if n==-2 else {'kind':'open','record_hex':corrupted if n==-1 else records[n]} for n in (0,0,-1,1,3,2,3,-2,4)]
   controls.pop('messages_hex');controls['actions']=actions
   require(same(request(t['reception'],'legacy.session.receive-sequence'),controls),'receiver did not preserve producer bytes and action order')
   control=dict(controls,actions=[{'kind':'open','record_hex':records[4]}])
   require(same(request(t['fresh_record_control'],'legacy.session.receive-sequence'),control),'close lacks fresh record control')
   if t['fresh_record_control']['status']=='PASS':require(same(t['fresh_record_control']['actual']['output'],{'results':[{'verdict':'ACCEPT','output':{'plaintext_hex':'65'}}]}),'invalid close positive control')
   a=t['reception'].get('actual')
   if a and a['verdict']=='ACCEPT' and isinstance(a.get('output',{}).get('results'),list) and len(a['output']['results'])==9:
    require(a['schema_version']==1 and a['case_id']==t['reception']['id'],'receiver observation identity')
    action_status=['PASS' if same(want,got) else 'FAIL' for want,got in zip(expected,a['output']['results'])]
   if t['reception']['status']=='PASS':require(action_status==['PASS']*9,'false replay PASS')
  else:
   for name in ('reception','fresh_record_control'):require(t[name]['status']=='NOT_RUN' and t[name].get('actual') is None,'receiver ran without producer')
  require(t['action_statuses']==action_status,'action counts derived from wrong observations')
  for s in action_status:counts[s]+=1
  stages=[t[k]['status'] for k in ('production','reception','fresh_record_control')]
  if 'FAIL' in stages:status='FAIL'
  elif status!='FAIL' and any(s!='PASS' for s in stages):status='INCOMPLETE'
 require(seen==expected_keys and same(counts,report['action_counts']) and report['status']==status,'replay aggregate mismatch')
 return counts

def check(root=ROOT):
 base=root/'docs/evidence/deployment'
 provenance=decode((base/'replay-provenance.json').read_bytes())
 for path,h in provenance['files'].items():
  p=(root/path).resolve();require(p.is_relative_to(root.resolve()) and sha(p.read_bytes())==h,'replay artifact drift')
 report=decode((base/'replay.json').read_bytes());counts=validate(report)
 revisions={c['repository']:c['revision'] for c in decode((root/'docs/evidence/core-source-lock.json').read_bytes())['cores']}
 for s in report['subjects']:require(s['revision']==revisions['sage' if s['name']=='sage-go' else 'rs-sage-core'],'core revision mismatch')
 return dict(report='docs/evidence/deployment/replay.json',action_counts=counts,status=report['status'],conformance='NOT_ESTABLISHED')
if __name__=='__main__':print(json.dumps(check()))
