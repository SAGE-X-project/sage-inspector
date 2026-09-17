"""Test retained record cores through the actual bounded scenario CLI."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile
from inspect_session import validate_scenario
from test_record010_adapters import ROOT, PINS, digest


def scenarios():
    source=json.loads((ROOT/'vectors/0.10.0/session-records.json').read_text())
    cases={c['id']:c for c in source['cases']}
    fixtures=[]
    for direction in ('c2s','s2c'):
        zero=cases[direction+'-open-0'];one=cases[direction+'-open-1']
        i=zero['input']
        receive=lambda c: ('open',dict(record_hex=c['input']['record_hex'],caller_aad_hex=c['input']['caller_aad_hex']),'ACCEPT',c['expected']['output'])
        rejected=lambda c: ('open',dict(record_hex=c['input']['record_hex'],caller_aad_hex=c['input']['caller_aad_hex']),'REJECT',{})
        bad=copy.deepcopy(zero)
        wire=bytearray.fromhex(bad['input']['record_hex']);wire[-1]^=1;bad['input']['record_hex']=wire.hex()
        close=('close',{},'ACCEPT',{})
        seal=lambda c: ('seal',dict(plaintext_hex=c['expected']['output']['plaintext_hex'],caller_aad_hex=c['input']['caller_aad_hex']),'ACCEPT',{'record_hex':c['input']['record_hex']})
        paths={
            'ordered':[receive(zero),receive(one)],
            'replay':[receive(zero),rejected(zero),receive(one)],
            'out-of-order':[receive(one),receive(zero),rejected(one)],
            'invalid-then-valid':[rejected(bad),receive(zero)],
            'close-first':[close,rejected(zero)],
            'receive-close':[receive(zero),close,rejected(one)],
            'send-close':[seal(zero),seal(one),close,('seal',dict(plaintext_hex='00',caller_aad_hex=''),'REJECT',{})],
        }
        for name, path in paths.items():
            fixture=dict(schema_version=2,protocol_version='0.10.0',profile='stateful-scenario',
                         id='record010-'+direction+'-'+name,sources=source['sources'],steps=[])
            effects=dict(core_open_success=0,core_seal_success=0,core_close_calls=0)
            create=dict(seed_hex=i['seed_hex'],th_hex=i['th_hex'],initiator=(direction=='c2s')==(name=='send-close'))
            actions=[('create',create,'ACCEPT',{'session_id':i['sid']})]+path
            for op,data,verdict,out in actions:
                if verdict=='ACCEPT' and op in ('open','seal','close'):
                    effects[{'open':'core_open_success','seal':'core_seal_success','close':'core_close_calls'}[op]]+=1
                fixture['steps'].append(dict(id='step-'+str(len(fixture['steps'])),operation='record010.'+op,input=data,
                    timeout_ms=5000,expected=dict(verdict=verdict,output=out),effects=copy.deepcopy(effects)))
            fixtures.append((fixture,None))
    base=copy.deepcopy(fixtures[0][0])
    for operation in ('control.clock.advance','record010.inspect','record010.restart','control.session.create'):
        f=copy.deepcopy(base);f['id']='unsupported-'+operation.replace('.','-')
        f['steps'].insert(1,dict(id='unsupported',operation=operation,input={},timeout_ms=5000,
            expected=dict(verdict='ACCEPT',output={}),effects=copy.deepcopy(f['steps'][0]['effects'])))
        fixtures.append((f,1))
    return fixtures


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('go','rust','runner','output'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args();output=args.output.resolve()
    if ROOT/'docs/evidence' in (output,*output.parents):parser.error('keep fresh results separate from historical evidence')
    output.mkdir(parents=True,exist_ok=False)
    report=dict(kind='record010-state-binding-tests',status='RUNNING',conformance='NOT_ESTABLISHED',
                runner_sha256=digest(args.runner),
                fixture_sha256=digest(ROOT/'vectors/0.10.0/session-records.json'),
                inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                subjects={},scenarios=[],malformed=[])
    try:
        for name in ('go','rust'):
            adapter=getattr(args,name).resolve();repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core')
            revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            assert revision==PINS[name] and not subprocess.check_output(['git','diff','HEAD','--'],cwd=repo)
            report['subjects'][name]=dict(revision=revision,executable_sha256=digest(adapter))
            for f,unsupported in scenarios():
                raw=json.dumps(f).encode()
                with tempfile.TemporaryDirectory() as tmp:
                    path=Path(tmp)/'scenario.json';path.write_bytes(raw)
                    p=subprocess.run([str(args.runner.resolve()),'-scenario',str(path),'-adapter',str(adapter),'-subject',name+'-record010-state','-revision',revision],capture_output=True,text=True,timeout=30)
                filename=name+'-'+f['id']+'.json';(output/filename).write_text(p.stdout)
                (output/(name+'-'+f['id']+'-input.json')).write_bytes(raw)
                report['scenarios'].append(dict(subject=name,id=f['id'],exit_code=p.returncode,path=filename,stderr=p.stderr))
                assert p.returncode==(0 if unsupported is None else 3),(f['id'],p.stdout,p.stderr)
                r=json.loads(p.stdout);validate_scenario(raw,r)
                assert r['subject']['executable_sha256']==digest(adapter)
                assert r['status']==('PASS' if unsupported is None else 'INCOMPLETE')
                if unsupported is not None:
                    assert r['steps'][unsupported]['status']=='UNSUPPORTED'
                    assert all(s['status']=='NOT_RUN' and 'actual' not in s for s in r['steps'][unsupported+1:])
            f=scenarios()[0][0]
            def request(step):return dict(schema_version=2,protocol_version='0.10.0',profile='stateful-scenario',case_id=f['id'],step_id=step['id'],operation=step['operation'],input=step['input'])
            first=request(f['steps'][0]);second=request(f['steps'][1])
            for mode in ('duplicate-step','changed-case','replace-session','unknown-control','missing-aad','wrong-schema'):
                q=copy.deepcopy(second)
                if mode=='duplicate-step':q['step_id']=first['step_id']
                if mode=='changed-case':q['case_id']='different'
                if mode=='replace-session':q.update(operation=first['operation'],input=first['input'])
                if mode=='unknown-control':q['input']['dispatch']=True
                if mode=='missing-aad':q['input'].pop('caller_aad_hex')
                if mode=='wrong-schema':q['schema_version']=1
                p=subprocess.run([str(adapter)],input=json.dumps(first)+'\n'+json.dumps(q)+'\n',capture_output=True,text=True,timeout=15)
                assert p.returncode!=0 and len(p.stdout.splitlines())==1,(name,mode,p.stdout,p.stderr)
                report['malformed'].append(dict(subject=name,mode=mode,exit_code=p.returncode,stderr=p.stderr))
        report['status']='PASS'
    except Exception as e:
        report.update(status='FAIL',reason=str(e));raise
    finally:(output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('14 retained-core scenarios and 4 unsupported controls per core; 12 malformed streams passed')


if __name__=='__main__':main()
