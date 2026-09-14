"""Validate bounded concurrent core observations; never infer all schedules from a stress run."""
import hashlib,json
from pathlib import Path
from integrate_evidence import decode,require,same
from check_replay_evidence import request
ROOT=Path(__file__).resolve().parents[1]

def parallel(actual,group):
 out=actual.get('output',{})
 if actual.get('verdict')!='ACCEPT' or not isinstance(out,dict) or set(out)!={'start_gate','workers_ready','workers'} or out.get('start_gate')!='all-ready' or type(out.get('workers_ready')) is not int or out['workers_ready']!=8 or not isinstance(out.get('workers'),list) or len(out['workers'])!=8:
  return 'FAIL',False,0
 workers=out['workers'];accepted={};overlap=False
 # The Go decoder rejects unknown fields and invalid numeric types before judgment.
 for w in workers:
  if not isinstance(w,dict) or set(w)-{'index','started_ns','finished_ns','verdict','output'} or any(type(w.get(k)) is not int or not 0<=w[k]<2**64 for k in ('index','started_ns','finished_ns')):
   return 'FAIL',False,0
 for i,w in enumerate(workers):
  if w['index']!=i or w['started_ns']==0 or w['finished_ns']<w['started_ns']:return 'FAIL',False,0
  overlap |= any(w['started_ns']<p['finished_ns'] and p['started_ns']<w['finished_ns'] for p in workers[:i])
  want='61' if group==0 else '63' if i<4 else '64'
  if w.get('verdict')=='ACCEPT':
   if group==0 and i>=4 or not same(w.get('output'),{'plaintext_hex':want}):return 'FAIL',overlap,8
   accepted[want]=accepted.get(want,0)+1
  elif w.get('verdict')=='REJECT':
   if w.get('output')!={}:return 'FAIL',overlap,8
  else:return 'FAIL',overlap,8
 if group==0 and accepted.get('61')!=1 or group==1 and (accepted.get('63')!=1 or accepted.get('64')!=1):return 'FAIL',overlap,8
 return ('PASS' if overlap else 'INCOMPLETE'),overlap,8

def validate(report):
 require(report['schema_version']==1 and report['protocol_version']=='0.10.0' and report['conformance']=='NOT_ESTABLISHED','concurrent report identity')
 require(report['created'] and report['environment'],'missing execution metadata')
 subjects={s['name']:s for s in report['subjects']}
 require(set(subjects)=={'sage-go','sage-rust'} and len(report['subjects'])==2,'core identities')
 require(len({s['executable_sha256'] for s in subjects.values()})==2,'same subject executable')
 keys={(a,b,d) for a,b in [('sage-go','sage-rust'),('sage-rust','sage-go')] for d in ('c2s','s2c')}
 seen=set();counts=dict.fromkeys(('PASS','FAIL','INCOMPLETE','NOT_RUN'),0);observed=0;status='PASS'
 for batch in report['batches']:
  key=(batch['sender'],batch['receiver'],batch['direction']);require(key in keys and key not in seen,'batch membership');seen.add(key)
  ident=key[0]+'-to-'+key[1]+'-'+key[2];require(batch['id']==ident and len(batch['rounds'])==8,'batch identity/round count')
  require(batch['production']['id']==ident+'-produce-sequence','producer identity')
  controls=dict(seed_hex='01'*32,sid='inspector-concurrent-exchange',direction=key[2],caller_aad_hex='73616765',messages_hex=['61','62','63','64','65'])
  require(same(request(batch['production'],'legacy.session.export-sequence'),controls),'producer controls')
  records=None
  if batch['production']['status']=='PASS':
   records=batch['production']['actual']['output']['records_hex'];require(len(records)==5 and len(set(records))==5,'producer records')
   for record in records:require(0<len(bytes.fromhex(record))<=2048 and bytes.fromhex(record).hex()==record,'invalid exported record')
  for number,round in enumerate(batch['rounds']):
   rid=ident+'-round-'+str(number);require(round['id']==rid and round['reception']['id']==rid+'-receive','round identity')
   checks=['NOT_RUN']*7;overlaps=[False,False]
   reception=round['reception']
   if records is None:require(reception['status']=='NOT_RUN' and reception.get('actual') is None,'receiver without producer')
   else:
    raw=bytes.fromhex(records[1]);bad=(raw[:-1]+bytes([raw[-1]^1])).hex()
    actions=[dict(kind='parallel_open',records_hex=[records[0]]*4+[bad]*4),dict(kind='open',record_hex=records[1]),dict(kind='open',record_hex=records[0]),dict(kind='parallel_open',records_hex=[records[2]]*4+[records[3]]*4),dict(kind='open',record_hex=records[2]),dict(kind='open',record_hex=records[3]),dict(kind='open',record_hex=records[4])]
    expected={k:v for k,v in controls.items() if k!='messages_hex'};expected['actions']=actions
    require(same(request(reception,'legacy.session.receive-sequence'),expected),'changed concurrent input/order')
    actual=reception.get('actual')
    if reception['status']=='PASS':
     results=actual['output']['results'];require(len(results)==7,'missing action results')
     for i,item in enumerate(results):
      if i in (0,3):
       group=0 if i==0 else 1;checks[i],overlaps[group],n=parallel(item,group);observed+=n
      else:
       expect=dict(verdict='REJECT',output={})
       if i in (1,6):expect=dict(verdict='ACCEPT',output={'plaintext_hex':'62' if i==1 else '65'})
       checks[i]='PASS' if same(item,expect) else 'FAIL'
   require(round['check_statuses']==checks and same(round['call_interval_overlap'],overlaps),'false checks/overlap')
   if batch['production']['status']=='FAIL' or reception['status']=='FAIL':status='FAIL'
   elif status!='FAIL' and reception['status']!='PASS':status='INCOMPLETE'
   for check in checks:
    counts[check]+=1
    if check=='FAIL':status='FAIL'
    elif check!='PASS' and status!='FAIL':status='INCOMPLETE'
 require(seen==keys and same(report['check_counts'],counts) and report['observed_workers']==observed and report['status']==status,'aggregate mismatch')
 return counts

def check(root=ROOT):
 base=root/'docs/evidence/deployment';provenance=decode((base/'concurrent-provenance.json').read_bytes())
 for path,sha in provenance['files'].items():
  p=(root/path).resolve();require(p.is_relative_to(root.resolve()) and hashlib.sha256(p.read_bytes()).hexdigest()==sha,'concurrent evidence drift')
 report=decode((base/'concurrent.json').read_bytes());counts=validate(report)
 revisions={c['repository']:c['revision'] for c in decode((root/'docs/evidence/core-source-lock.json').read_bytes())['cores']}
 for s in report['subjects']:require(s['revision']==revisions['sage' if s['name']=='sage-go' else 'rs-sage-core'],'core revision drift')
 return dict(report='docs/evidence/deployment/concurrent.json',check_counts=counts,observed_workers=report['observed_workers'],status=report['status'],conformance='NOT_ESTABLISHED')
if __name__=='__main__':print(json.dumps(check()))
