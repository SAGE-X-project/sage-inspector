"""Bounded local record tests against explicitly supplied real core adapters.

No sockets, host actions, concurrency probes or exploit programs are launched.
The report is separate from the frozen historical conformance catalog.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PINS = {'go': '6c46fadf5df748801c1868b94444327199225ed4',
        'rust': '9fc5f044589929fc00b430219b1887af0946c7a4'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', required=True, type=Path)
    parser.add_argument('--rust', required=True, type=Path)
    parser.add_argument('--runner', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if ROOT/'docs/evidence' in (output, *output.parents):
        parser.error('keep fresh test results outside archived evidence')
    output.mkdir(parents=True, exist_ok=False)
    executables = {name: getattr(args, name).resolve() for name in PINS}
    fixture = ROOT/'vectors/0.10.0/session-records.json'
    report = dict(kind='record010-binding-tests', status='RUNNING',
                  conformance='NOT_ESTABLISHED', python=platform.python_version(),
                  platform=platform.platform(), fixture_sha256=digest(fixture),
                  inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                  runner_sha256=digest(args.runner), subjects={}, suites={}, exchanges=[], controls=[])
    def save():
        (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    def observe(name, operation, data, case, malformed=False):
        q=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',
               case_id=case,operation='sage.session.record010.'+operation,input=data)
        raw=json.dumps(q)
        p=subprocess.run([str(executables[name])],input=raw,text=True,capture_output=True,timeout=15)
        result=dict(subject=name,request=q,request_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                    exit_code=p.returncode,stderr=p.stderr)
        if malformed:
            assert p.returncode!=0 and not p.stdout, result
            result['status']='PASS'
            report['controls'].append(result)
            return None
        assert p.returncode==0, result
        o=json.loads(p.stdout)
        assert set(o)=={'schema_version','case_id','verdict','output'} and type(o['schema_version']) is int and o['schema_version']==1 and o['case_id']==case, o
        result['actual']=o
        return result
    try:
        for name, executable in executables.items():
            repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core')
            revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            assert revision==PINS[name], (name,'review a new core revision before testing')
            # Existing unrelated untracked files are not used by these bindings.
            assert not subprocess.check_output(['git','diff','HEAD','--'],cwd=repo), 'tracked core source changed'
            report['subjects'][name]=dict(revision=revision,executable_sha256=digest(executable))
        suite=json.loads(fixture.read_text())
        suite['id']='record010-binding-records'
        suite['cases']=[c for c in suite['cases'] if c['operation']!='sage.session.key']
        assert len(suite['cases'])==37
        for c in suite['cases']:
            c['operation']=c['operation'].replace('.record.','.record010.')
            c['input'].pop('sid') # Core derives sid; this API does not accept envelope tuple controls.
        with tempfile.TemporaryDirectory() as tmp:
            suite_path=Path(tmp)/'records.json';suite_path.write_text(json.dumps(suite))
            for name, executable in executables.items():
                p=subprocess.run([str(args.runner.resolve()),'-suite',str(suite_path),'-adapter',str(executable),
                                  '-subject',name+'-record010','-revision',PINS[name]],capture_output=True,text=True,timeout=120)
                (output/(name+'-suite.json')).write_text(p.stdout)
                report['suites'][name]=dict(exit_code=p.returncode,stderr=p.stderr,path=name+'-suite.json')
                assert p.returncode==0, (name,p.stderr,p.stdout[-2000:])
                r=json.loads(p.stdout)
                assert r['status']=='PASS' and len(r['results'])==37
        for sender, receiver in (('go','rust'),('rust','go')):
            for direction in ('c2s','s2c'):
                label=sender+'-to-'+receiver+'-'+direction
                controls=dict(seed_hex='01'*32,th_hex='02'*32,direction=direction,
                              caller_aad_hex='73616765',plaintext=dict(byte=97,length=32))
                produced=observe(sender,'export',controls,label+'-produce')
                entry=dict(id=label,production=produced,checks=[]);report['exchanges'].append(entry)
                o=produced['actual'];assert o['verdict']=='ACCEPT'
                value=o['output'];wire=bytes.fromhex(value['record_hex'])
                assert len(wire)==value['record_bytes']==68
                assert hashlib.sha256(wire).hexdigest()==value['record_sha256']
                import base64
                sid=base64.urlsafe_b64encode(hashlib.sha256(b'sage-session|0.10.0'+bytes.fromhex(controls['th_hex'])).digest()[:16]).decode().rstrip('=')
                assert value['session_id']==sid
                opening={k:v for k,v in controls.items() if k!='plaintext'}
                opening['record_hex']=value['record_hex']
                positive=observe(receiver,'open',opening,label+'-positive');entry['checks'].append(positive)
                assert positive['actual']['verdict']=='ACCEPT' and positive['actual']['output']=={'plaintext_hex':'61'*32}
                changed=copy.deepcopy(opening);changed['th_hex']='04'*32
                negative=observe(receiver,'open',changed,label+'-different-transcript');entry['checks'].append(negative)
                negative['positive_control']='PASS'
                assert negative['actual']['verdict']=='REJECT' and negative['actual']['output']=={}
        base=copy.deepcopy(next(c['input'] for c in suite['cases'] if c['id']=='c2s-open-0'))
        for name in executables:
            for field,value in [('seed_hex',None),('th_hex','zz'),('direction','invalid'),('caller_aad_hex',None),('record_hex','zz'),('sid','ignored-input'),('expected',{})]:
                data=copy.deepcopy(base);data[field]=value
                observe(name,'open',data,name+'-malformed-'+field,malformed=True)
        report['status']='PASS'
    except Exception as error:
        report.update(status='FAIL',reason=str(error))
        raise
    finally:
        save()
    print('37 fixed record cases per core, four paired exchanges and 14 malformed controls passed')


if __name__=='__main__':
    main()
