"""Real local core journals and process recovery; no signatures, tools or network."""
import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path
import platform
import subprocess
import tempfile
from test_record010_adapters import PINS

ROOT=Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go',type=Path,required=True)
    parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--development',action='store_true')
    args=parser.parse_args()
    output=args.output.resolve()
    if ROOT/'docs/evidence' in (output,*output.parents):parser.error('preserve historical evidence')
    output.mkdir(parents=True,exist_ok=False)
    (output/'raw').mkdir();(output/'journals').mkdir()
    fixture_path=ROOT/'vectors/0.10.0/execution-ledger010.json'
    fixture=json.loads(fixture_path.read_bytes())
    programs={name:getattr(args,name).resolve() for name in PINS}
    report=dict(kind='execution-ledger010-core-storage',status='RUNNING',conformance='NOT_ESTABLISHED',
                scope='Actual core storage with opaque synthetic envelopes; no authentication, dispatch or host enforcement.',
                development=args.development,platform=platform.platform(),fixture_sha256=digest(fixture_path),
                inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                subjects={},scenarios=[],restarts=[],controls=[],files={})

    def save():
        (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')

    def snapshot(path,label):
        if not path.exists():return
        target=output/'journals'/(label+'.journal')
        target.write_bytes(path.read_bytes());report['files'][str(target.relative_to(output))]=digest(target);save()

    def execute(name,label,path,mode,requests,expected=None,invalid=False):
        wire=''.join(json.dumps(q)+'\n' for q in requests)
        raw=dict(subject=name,mode=mode,input=requests,input_sha256=hashlib.sha256(wire.encode()).hexdigest())
        target=output/'raw'/(label+'.json')
        try:
            process=subprocess.run([str(programs[name]),str(path),mode],input=wire,text=True,capture_output=True,timeout=20)
            raw.update(exit_code=process.returncode,stdout=process.stdout,stderr=process.stderr)
        except subprocess.TimeoutExpired as error:
            raw.update(timeout=True,stdout=str(error.stdout),stderr=str(error.stderr));raise
        finally:
            target.write_text(json.dumps(raw,indent=2)+'\n');report['files'][str(target.relative_to(output))]=digest(target);save()
        assert not process.stderr,raw
        if invalid:
            assert process.returncode==2 and not process.stdout,raw
        else:
            assert process.returncode==0,raw
            assert [json.loads(line) for line in process.stdout.splitlines()]==expected,raw
        snapshot(path,label)

    ok=dict(ok=True,changed=True,entry=None)
    unchanged=dict(ok=True,changed=False,entry=None)
    denied=dict(ok=False,changed=False,entry=None)
    try:
        for name,program in programs.items():
            repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core')
            revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            dirty=bool(subprocess.check_output(['git','diff','HEAD','--'],cwd=repo))
            if not args.development:
                assert revision==PINS[name] and not dirty,'unreviewed core source'
            copied=repo/('pkg/agent/execution010/testdata/ledger.json' if name=='go' else 'tests/fixtures/execution-ledger010.json')
            assert digest(copied)==digest(fixture_path),'fixture mismatch'
            report['subjects'][name]=dict(revision=revision,dirty=dirty,executable_sha256=digest(program))
        assert len(fixture['cases'])==14 and sum(len(c['steps']) for c in fixture['cases'])==72
        with tempfile.TemporaryDirectory() as directory:
            temporary=Path(directory)
            for name in programs:
                for case in fixture['cases']:
                    label=name+'-'+case['id']
                    execute(name,label,temporary/label,'create',[s['request'] for s in case['steps']],[s['expected'] for s in case['steps']])
                    report['scenarios'].append(dict(id=label,status='PASS'))
            base=fixture['cases'][0]['steps'][0]['request']['entry']
            lookup=dict(action='lookup',issuer=base['issuer'],call_id=base['call_id'])
            for writer,reader in itertools.product(programs,repeat=2):
                for state in ('RESERVED','EXECUTING','COMPLETED','REJECTED','UNKNOWN'):
                    label=writer+'-to-'+reader+'-'+state.lower();path=temporary/label
                    entry=copy.deepcopy(base)
                    requests=[dict(action='commit',entry=copy.deepcopy(entry))]
                    if state=='REJECTED':
                        entry.update(state=state,result_hex='7b7d');requests=[dict(action='commit',entry=copy.deepcopy(entry))]
                    elif state in ('EXECUTING','COMPLETED'):
                        entry['state']='EXECUTING';requests.append(dict(action='commit',entry=copy.deepcopy(entry)))
                        if state=='COMPLETED':
                            entry.update(state=state,result_hex='7b7d');requests.append(dict(action='commit',entry=copy.deepcopy(entry)))
                    elif state=='UNKNOWN':
                        entry.update(state=state,result_hex='7b7d');requests.append(dict(action='commit',entry=copy.deepcopy(entry)))
                    execute(writer,label+'-write',path,'create',requests+[dict(action='abandon')],[ok]*len(requests)+[unchanged])
                    # Only the owned child exited. Do not clear a lock before proving it is gone.
                    assert Path(str(path)+'.lock').exists()
                    execute(reader,label+'-locked',path,'reopen',[],invalid=True)
                    Path(str(path)+'.lock').unlink()
                    if state in ('RESERVED','EXECUTING'):entry.update(state='UNKNOWN',result_hex='')
                    attempt=copy.deepcopy(base);attempt['state']='EXECUTING'
                    execute(reader,label+'-recover',path,'reopen',[lookup,dict(action='commit',entry=attempt)],
                            [dict(ok=True,changed=False,entry=entry),denied])
                    execute(reader,label+'-repeat',path,'reopen',[lookup],[dict(ok=True,changed=False,entry=entry)])
                    report['restarts'].append(dict(id=label,status='PASS'))
            for name in programs:
                for control in ('missing','torn','duplicate-writer'):
                    label=name+'-'+control;path=temporary/label
                    if control=='missing':
                        execute(name,label+'-setup',path,'create',[],[]);path.unlink()
                    elif control=='torn':
                        execute(name,label+'-setup',path,'create',[],[])
                        with path.open('ab') as stream:stream.write(b'{')
                    else:
                        execute(name,label+'-setup',path,'create',[dict(action='abandon')],[unchanged])
                    execute(name,label,path,'reopen',[],invalid=True)
                    report['controls'].append(dict(id=label,status='PASS'))
        report['status']='PASS'
    except Exception as error:
        report.update(status='FAIL',reason=str(error));raise
    finally:
        save()
    print(json.dumps(dict(status=report['status'],scenarios=len(report['scenarios']),restarts=len(report['restarts']),controls=len(report['controls']),conformance=report['conformance'])))


if __name__=='__main__':
    main()
