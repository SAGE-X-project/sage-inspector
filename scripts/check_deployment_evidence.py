"""Validate archived live exchanges and separately scoped host readiness evidence."""
import collections
import hashlib
import json
from pathlib import Path
from inspect_host import inventory
from integrate_evidence import decode, require, same

ROOT=Path(__file__).resolve().parents[1]
MUTATIONS=('valid','ciphertext','aad','seed','direction','sid','transcript')

def digest(raw):return hashlib.sha256(raw).hexdigest()

def validate_exchange(report):
    require(report['schema_version']==1 and report['protocol_version']=='0.10.0' and report['conformance']=='NOT_ESTABLISHED','exchange identity')
    require(report['environment'] and report['created'],'missing execution context')
    subjects={s['name']:s for s in report['subjects']}
    require(set(subjects)=={'sage-go','sage-rust'} and len(report['subjects'])==2,'two core identities required')
    require(len({s['executable_sha256'] for s in subjects.values()})==2,'same executable is not independent exchange evidence')
    expected={(a,b,d) for a,b in [('sage-go','sage-rust'),('sage-rust','sage-go')] for d in ('c2s','s2c')}
    counts=dict.fromkeys(('PASS','FAIL','UNSUPPORTED','NOT_RUN'),0)
    seen=set()
    for exchange in report['exchanges']:
        key=(exchange['sender'],exchange['receiver'],exchange['direction'])
        require(key in expected and key not in seen,'duplicate or unexpected direction');seen.add(key)
        ident='-to-'.join(key[:2])+'-'+key[2]
        require(exchange['id']==ident and len(exchange['checks'])==7,'incomplete exchange checks')
        production=exchange['production']
        require(production['id']==ident+'-produce','production identity')
        wire=None
        for index,step in enumerate([production]+exchange['checks']):
            require(step['status'] in counts,'unknown exchange status');counts[step['status']]+=1
            expected_verdict='ACCEPT' if index<=1 else 'REJECT'
            require(step['expected_verdict']==expected_verdict,'changed exchange expectation')
            if index:
                require(step['id']==ident+'-'+MUTATIONS[index-1],'changed check membership/order')
                if index>1:require(step['positive_control']==exchange['checks'][0]['status'],'lost positive control')
            if step['status']=='NOT_RUN':
                require(production['status']!='PASS' and step.get('actual') is None,'false unexecuted check');continue
            q=step['request']
            require(q['case_id']==step['id'] and q['schema_version']==1 and q['protocol_version']=='0.10.0' and q['profile']=='primitive-foundation','request identity')
            raw=json.dumps(q,separators=(',',':'),ensure_ascii=False).encode()
            require(digest(raw)==step['request_sha256'],'request hash changed')
            operation='sage.session.record.export' if index==0 else 'sage.session.record.open.bound' if index==7 else 'sage.session.record.open'
            require(q['operation']==operation,'wrong operation')
            actual=step.get('actual')
            if step['status'] in ('PASS','UNSUPPORTED'):
                require(actual and actual['schema_version']==1 and actual['case_id']==step['id'],'observation identity')
                require(actual['verdict']==('UNSUPPORTED' if step['status']=='UNSUPPORTED' else expected_verdict),'false exchange PASS')
                if actual['verdict']!='ACCEPT':require(actual['output']=={},'nonaccept output')
            if step['status']=='FAIL':require(step.get('reason'),'failure without reason')
            if index==0 and step['status']=='PASS':
                output=actual['output'];wire=bytes.fromhex(output['record_hex'])
                require(0<len(wire)<=4096 and len(wire)==output['record_bytes'] and digest(wire)==output['record_sha256'],'invalid exported wire')
            if index and production['status']=='PASS':
                original=dict(production['request']['input']);original.pop('plaintext')
                original['record_hex']=wire.hex()
                mutation=MUTATIONS[index-1]
                if mutation=='ciphertext':original['record_hex']=(wire[:-1]+bytes([wire[-1]^1])).hex()
                if mutation=='aad':original['caller_aad_hex']='00'
                if mutation=='seed':original['seed_hex']='03'*32
                if mutation=='direction':original['direction']='s2c' if key[2]=='c2s' else 'c2s'
                if mutation=='sid':original['sid']='different-session'
                if mutation=='transcript':original['th_hex']='04'*32
                require(same(q['input'],original),'receiver did not use producer bytes and declared mutation')
                if index==1 and step['status']=='PASS':require(actual['output']=={'plaintext_hex':'61'*32},'wrong recovered plaintext')
    require(seen==expected and same(counts,report['counts']),'missing exchanges or changed counts')
    inferred='FAIL' if counts['FAIL'] else 'INCOMPLETE' if counts['UNSUPPORTED'] or counts['NOT_RUN'] else 'PASS'
    require(report['status']==inferred,'false exchange aggregate')
    return counts

def check(root=ROOT):
    base=root/'docs/evidence/deployment'
    provenance=decode((base/'provenance.json').read_bytes())
    for path,sha in provenance['files'].items():
        resolved=(root/path).resolve();require(resolved.is_relative_to(root.resolve()),'provenance path escape')
        require(digest(resolved.read_bytes())==sha,'deployment evidence drift: '+path)
    exchange=decode((base/'exchange.json').read_bytes());counts=validate_exchange(exchange)
    lock=decode((root/'docs/evidence/core-source-lock.json').read_bytes())
    revisions={c['repository']:c['revision'] for c in lock['cores']}
    for s in exchange['subjects']:require(s['revision']==revisions['sage' if s['name']=='sage-go' else 'rs-sage-core'],'core revision drift')
    host=decode((base/'host/summary.json').read_bytes());manifest,fixtures=inventory(root)
    require(host['manifest_sha256']==manifest and host['conformance']=='NOT_ESTABLISHED','host manifest drift')
    # This archived delivery has no real host. Live inspection uses inspect_host.py;
    # adding future executed evidence requires explicit review of this baseline.
    require(host['binding'] is None and host['status']=='INCOMPLETE','unreviewed host execution claim')
    require(len(host['scenarios'])==len(fixtures),'missing host scenarios')
    for row,(entry,_,_) in zip(host['scenarios'],fixtures):
        require(row['id']==entry['id'] and row['fixture_sha256']==entry['sha256'] and row['status']=='NOT_RUN' and row['observed_effects'] is None,'false host coverage')
    print(json.dumps({'exchange':counts,'host_NOT_RUN':len(fixtures),'conformance':'NOT_ESTABLISHED'}))
    from check_replay_evidence import check as check_replay
    replay = check_replay(root)
    from check_concurrent_evidence import check as check_concurrent
    concurrent = check_concurrent(root)
    from check_close_evidence import check as check_close
    close_race = check_close(root)
    return dict(close_race=close_race,concurrent=concurrent,replay=replay,exchange_report='docs/evidence/deployment/exchange.json',exchange_counts=counts,
                host_report='docs/evidence/deployment/host/summary.json',host_not_run=len(fixtures),conformance='NOT_ESTABLISHED')

if __name__=='__main__':check()
