"""Real bounded journal processes; no network, production state or session restore."""
import argparse,hashlib,itertools,json,subprocess,tempfile
from pathlib import Path
from test_completion010 import ROOT,digest
from test_record010_adapters import PINS

def step(action,ok=True,unix=460,mono_ms=360000,**kw):return dict(action=action,ok=ok,unix=unix,mono_ms=mono_ms,**kw)
def controls(steps):return [{k:v for k,v in s.items() if k not in ('ok','calls')} for s in steps]
def execute(program,path,steps,log):
 sent=controls(steps);p=subprocess.run([str(program),str(path)],input=''.join(json.dumps(s)+'\n' for s in sent),text=True,capture_output=True,timeout=20);log(dict(program=str(program),controls=sent,exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr))
 assert p.returncode==0 and not p.stderr,(p.returncode,p.stderr)
 results=[json.loads(s) for s in p.stdout.splitlines()];assert results==[dict(ok=s['ok'],calls=s.get('calls',0)) for s in steps],(results,steps)

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('go','rust','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--development',action='store_true');args=p.parse_args();out=args.output.resolve()
 if ROOT/'docs/evidence' in (out,*out.parents):p.error('preserve historical evidence')
 out.mkdir(parents=True,exist_ok=False);raw=(out/'raw.jsonl').open('w')
 def log(v):raw.write(json.dumps(v)+'\n');raw.flush()
 fixture=ROOT/'vectors/0.10.0/replay-journal010.json';f=json.loads(fixture.read_text());programs={name:getattr(args,name).resolve() for name in PINS}
 report=dict(kind='replay-journal010',status='RUNNING',conformance='NOT_ESTABLISHED',development=args.development,scope=f['scope'],fixture_sha256=digest(fixture),subjects={},scenarios=[],restarts=[],raw='raw.jsonl',inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip())
 def save():(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 (out/'journals').mkdir()
 def snapshot(path,label):
  destination=out/'journals'/label;destination.write_bytes(path.read_bytes());return str(destination.relative_to(out))
 save()
 try:
  for name,program in programs.items():
   repo=ROOT.parent/('sage' if name=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip();diff=subprocess.check_output(['git','diff','HEAD','--'],cwd=repo)
   if not args.development:assert rev==PINS[name] and not diff
   shared=repo/('pkg/agent/hpke/testdata/replay-journal010.json' if name=='go' else 'tests/fixtures/replay-journal010.json');assert digest(shared)==digest(fixture)
   report['subjects'][name]=dict(revision=rev,executable_sha256=digest(program),tracked_diff_sha256=hashlib.sha256(diff).hexdigest())
  with tempfile.TemporaryDirectory() as directory:
   tmp=Path(directory)
   for name,program in programs.items():
    for case in f['cases']:
     path=tmp/(name+'-'+case['id']);execute(program,path,case['steps'],log);assert not Path(str(path)+'.lock').exists();report['scenarios'].append(dict(id=name+'-'+case['id'],status='PASS',journal_sha256=digest(path) if path.exists() else None,journal=snapshot(path,name+'-'+case['id']) if path.exists() else None));save()
   for writer,reader in itertools.product(programs,repeat=2):
    for kind in ('clean','abandoned','failed-gate','missing','partial'):
     label=writer+'-to-'+reader+'-'+kind;path=tmp/label
     init=[step('open',unix=100,mono_ms=0,create=True)]
     if kind=='failed-gate':init+=[step('record',False,gate=False,calls=1)]
     else:init+=[step('reserve')]
     init+=[step('abandon' if kind=='abandoned' else 'close')];execute(programs[writer],path,init,log)
     original=digest(path);before=snapshot(path,label+'.before')
     if kind=='abandoned':
      lock=Path(str(path)+'.lock');assert lock.exists();execute(programs[reader],path,[step('open',False,mono_ms=0)],log)
      # The child exited. This is explicit test-operator recovery of its own
      # temporary lock, never automatic library stale-lock removal.
      lock.unlink()
     if kind=='missing':
      path.unlink();execute(programs[reader],path,[step('open',False,mono_ms=0)],log);assert not path.exists()
      execute(programs[reader],path,[step('open',create=True,mono_ms=0),step('ready',False,mono_ms=0),step('reserve',False,mono_ms=0),step('ready',True,unix=820,mono_ms=360000),step('reserve',unix=820,expires=1100)],log)
     elif kind=='partial':
      # Offline interrupted-file simulation on a synthetic local journal.
      with path.open('ab') as stream:stream.write(b'{')
      execute(programs[reader],path,[step('open',False,mono_ms=0)],log)
     else:
      execute(programs[reader],path,[step('open',mono_ms=0),step('ready',mono_ms=0),step('reserve',False,mono_ms=0,nonce='other'),step('reserve',False,mono_ms=0,id='other'),step('record',mono_ms=0,id='new',nonce='new',gate=True,calls=1),step('close',mono_ms=0)],log)
      execute(programs[writer],path,[step('open',mono_ms=0),step('reserve',False,mono_ms=0,id='new',nonce='new')],log)
     assert not Path(str(path)+'.lock').exists();report['restarts'].append(dict(id=label,status='PASS',before_sha256=original,after_sha256=digest(path),before=before,after=snapshot(path,label+'.after')));save()
  report['status']='PASS'
 except Exception as exc:report.update(status='FAIL',reason=str(exc));raise
 finally:raw.close();report['raw_sha256']=digest(out/'raw.jsonl');save()
 print('24 journal scenarios and 20 cross-process recovery scenarios passed')
if __name__=='__main__':main()
