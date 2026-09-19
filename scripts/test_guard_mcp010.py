"""Actual MCP mapping, fresh authentication and client consumption across cores."""
import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile
from test_record010_adapters import PINS
from test_guard_client010 import config, observation, event, outer, verify_rows

ROOT=Path(__file__).resolve().parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def wire(v):return json.dumps(v,separators=(',',':'),ensure_ascii=False,sort_keys=True)

def check_answer(case,answer):
    if answer.get('schema_version')!=1 or answer.get('case_id')!=case['id']:raise ValueError('response identity')
    if answer['verdict']!=('ACCEPT' if case['accept'] else 'REJECT'):raise ValueError('acceptance mismatch '+case['id'])
    o=answer['output']
    if not case['accept']:
        if o!={}:raise ValueError('unauthenticated output')
        return
    expected=json.loads(bytes.fromhex(case['input']['wire_hex']))['structuredContent']
    status=expected['result']['status']
    if set(o)!={'status','success','error','wire_hex'} or o['status']!=status or o['success']!=(status=='completed') or o['error']!={'completed':'','pending':'unavailable','unknown':'operation_failed','rejected':'policy_denied'}[status]:raise ValueError('carriage mismatch')
    actual=json.loads(bytes.fromhex(o['wire_hex']))
    if actual!={'structuredContent':expected,'content':[{'type':'text','text':wire(expected)}],'isError':status!='completed'}:raise ValueError('unsigned content or changed representation')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('go','rust','go-client','rust-client','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--development',action='store_true');a=p.parse_args();out=a.output.resolve()
    if out.is_relative_to(ROOT/'docs/evidence'):p.error('preserve historical evidence')
    out.mkdir(parents=True,exist_ok=False)
    programs={n:getattr(a,n).resolve(strict=True) for n in PINS};clients={n:getattr(a,n+'_client').resolve(strict=True) for n in PINS}
    raw=(ROOT/'vectors/0.10.0/guard-mcp.json').read_bytes();v=json.loads(raw)
    report=dict(kind='guard-mcp-bindings',status='RUNNING',conformance='NOT_ESTABLISHED',lifecycle=dict(NOT_RUN=37),development=a.development,fixture_sha256=sha(raw),inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),subjects={},cases=[],exchanges=[],clients=[],files={},processes=0)
    audit=[]
    def retain(name,data):(out/name).write_bytes(data);report['files'][name]=sha(data)
    def run(label,program,request,args=(),lines=False):
        data=(''.join(wire(q)+'\n' for q in request) if lines else wire(request)+'\n').encode()
        proc=subprocess.run([str(program),*map(str,args)],input=data,capture_output=True,timeout=20)
        report['processes']+=1
        retain(label+'.json',(json.dumps(dict(input=request,input_sha256=sha(data),exit_code=proc.returncode,stdout=proc.stdout.decode(),stderr=proc.stderr.decode()),indent=2)+'\n').encode())
        if proc.returncode or proc.stderr:raise ValueError('adapter failed '+label)
        return [json.loads(x) for x in proc.stdout.splitlines()] if lines else json.loads(proc.stdout)
    def execute(name,label,case):
        q=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',case_id=case['id'],operation='sage.guard.mcp.verify',input=case['input'])
        answer=run(label,programs[name],q);check_answer(case,answer)
        if case['accept']:
            envelope=json.loads(bytes.fromhex(answer['output']['wire_hex']))['structuredContent'];f=case['input']
            audit.append(dict(envelope_hex=wire(envelope).encode().hex(),intent_hex=wire(f['intent_envelope']).encode().hex(),status=envelope['result']['status'],output=envelope['result']['output'],created=envelope['result']['created']))
        return answer
    try:
        for n,pin in PINS.items():
            source=ROOT.parent/('sage' if n=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
            if not a.development and rev!=pin:raise ValueError('revision mismatch')
            report['subjects'][n]=dict(revision=rev,adapter_sha256=sha(programs[n].read_bytes()),client_sha256=sha(clients[n].read_bytes()))
        published={}
        for n in PINS:
            for c in v['cases']:
                label=n+'-case-'+str(len(report['cases']));answer=execute(n,label,c)
                report['cases'].append(dict(subject=n,id=c['id'],status='PASS',evidence=label+'.json'))
                if c['accept']:published[n,c['id']]=answer['output']['wire_hex']
        for writer,reader in itertools.product(PINS,repeat=2):
            for c in v['cases']:
                if not c['accept']:continue
                c=copy.deepcopy(c);c['input']['wire_hex']=published[writer,c['id']]
                label=writer+'-to-'+reader+'-'+c['id'];execute(reader,label,c);report['exchanges'].append(dict(id=label,status='PASS'))
        cv=json.loads((ROOT/'vectors/0.10.0/guard-client.json').read_text())
        envelope=json.loads(bytes.fromhex(cv['results']['completed']));valid=wire(dict(structuredContent=envelope,content=[dict(type='text',text=wire(envelope))],isError=False)).encode().hex()
        with tempfile.TemporaryDirectory(prefix='guard-mcp-') as tmp:
            for n in PINS:
                for scenario in ('valid','mismatch','unsupported-version','revoked'):
                    label=n+'-client-'+scenario;path=Path(tmp)/label;id=outer(1)
                    cmds=[config(cv),dict(action='begin',id=id)]
                    wants=[observation(),observation(id=id,intent_hex=cv['input']['envelope_hex'],handoffs=1)]
                    rows=[event('open',intent_hex=cv['input']['envelope_hex']),event('send',id,1700000000000),event('close',id)]
                    if scenario=='revoked':cmds.append(dict(action='set',field='result_active',value=False));wants.append(observation(handoffs=1))
                    encoded=valid
                    if scenario=='mismatch':bad=json.loads(bytes.fromhex(valid));bad['content'][0]['text']='{}';encoded=wire(bad).encode().hex()
                    cmds.append(dict(action='accept_mcp',id=id,envelope_hex=encoded,mcp_version='2024-11-05' if scenario=='unsupported-version' else '2025-06-18'))
                    if scenario=='valid':wants.append(observation(status='completed',first=True,output_hex=wire(envelope['result']['output']).encode().hex(),handoffs=1));rows.append(event('terminal',id,result_hex=cv['results']['completed']))
                    else:wants.append(observation(ok=False,handoffs=1))
                    cmds.extend([dict(action='accept',id=id,envelope_hex=cv['results']['completed']),dict(action='close')]);wants.extend([observation(ok=False,handoffs=1),observation(handoffs=1)])
                    observed=run(label,clients[n],cmds,(path,'create'),True)
                    if observed!=wants:raise ValueError('client consumption '+label)
                    data=path.read_bytes();retain(label+'.journal',data);verify_rows(data,rows)
                    if path.with_name(path.name+'.lock').exists():raise ValueError('healthy lock not removed')
                    report['clients'].append(dict(id=label,status='PASS'))
        proof=dict(public_key_hex=v['cases'][0]['input']['public_key_hex'],cases=audit)
        retain('signatures.json',(json.dumps(proof,indent=2)+'\n').encode())
        result=subprocess.run(['node',str(ROOT/'scripts/check_guard_results010.js')],input=json.dumps(proof),text=True,capture_output=True,timeout=20)
        retain('signature-audit.json',(json.dumps(dict(exit_code=result.returncode,stdout=result.stdout,stderr=result.stderr))+'\n').encode())
        if result.returncode:raise ValueError('independent signature audit '+result.stderr)
        if report['processes']!=88 or len(report['cases'])!=64 or len(report['exchanges'])!=16 or len(report['clients'])!=8 or len(audit)!=24:raise ValueError('coverage mismatch')
        report.update(status='PASS',independent_signature_checks=len(audit))
    except (OSError,ValueError,KeyError,subprocess.TimeoutExpired) as e:report.update(status='FAIL',error=str(e))
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));return report['status']!='PASS'
if __name__=='__main__':raise SystemExit(main())
