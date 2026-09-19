"""Run real core dispatch with a controlled registry Source, never a live resolver."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from test_record010_adapters import PINS
from test_guard_results010 import validate_storage, state
ROOT=Path(__file__).resolve().parents[1]
MODES=('valid','boundary','revoked','unready','source','clock','stale','rollback')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def expected(mode):
    if mode not in MODES:raise ValueError('unknown scenario')
    success=mode in ('valid','boundary')
    return dict(ok=success,committed=success,effects=int(success),arguments='{"path":"public.txt"}' if success else '',reads=8 if mode in ('clock','rollback') else 9)
def validate(mode, actual, journal, envelope):
    want=expected(mode)
    if type(actual) is not dict or set(actual)!=set(want) or any(type(actual[k]) is not type(v) for k,v in want.items()) or actual!=want:raise ValueError('dispatch or observation mismatch')
    states=['RESERVED','EXECUTING']+([] if mode in ('valid','boundary') else ['UNKNOWN'])
    validate_storage(journal,bytes.fromhex(envelope),[state(x) for x in states])

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('go','rust','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--development',action='store_true');a=p.parse_args();out=a.output.resolve()
    if out.is_relative_to(ROOT/'docs/evidence'):p.error('preserve historical evidence')
    out.mkdir(parents=True,exist_ok=False)
    suite=(ROOT/'vectors/0.10.0/guard-records.json').read_bytes();f=next(c['input'] for c in json.loads(suite)['cases'] if c['id']=='intent-valid')
    report=dict(kind='guard-registry-authority',status='RUNNING',conformance='NOT_ESTABLISHED',lifecycle=dict(NOT_RUN=37),live_registry='NOT_RUN',registry_source='CONTROLLED_TEST_SOURCE',registry_store='IN_MEMORY_TEST_STORE',development=a.development,fixture_sha256=sha(suite),inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),subjects={},cases=[],files={})
    def retain(name,raw): (out/name).write_bytes(raw);report['files'][name]=sha(raw)
    try:
        for lang in ('go','rust'):
            binary=getattr(a,lang).resolve(strict=True);repo=ROOT.parent/('sage' if lang=='go' else 'rs-sage-core');rev=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            if not a.development and rev!=PINS[lang]:raise ValueError('core revision mismatch')
            report['subjects'][lang]=dict(revision=rev,adapter_sha256=sha(binary.read_bytes()))
            for mode in MODES:
                with tempfile.TemporaryDirectory() as directory:
                    path=Path(directory)/'journal';q=json.dumps(dict(mode=mode,input=f),sort_keys=True,separators=(',',':')).encode();proc=subprocess.run([str(binary),str(path)],input=q,capture_output=True,timeout=20)
                    label=lang+'-'+mode;record=dict(input_hex=q.hex(),stdout_hex=proc.stdout.hex(),stderr_hex=proc.stderr.hex(),exit_code=proc.returncode)
                    retain(label+'.json',(json.dumps(record,indent=2)+'\n').encode())
                    if proc.returncode or proc.stderr:raise ValueError('adapter execution failure')
                    raw=path.read_bytes();retain(label+'.journal',raw)
                    validate(mode,json.loads(proc.stdout),raw,f['envelope_hex'])
                    if path.with_name(path.name+'.lock').exists():raise ValueError('lock retained')
                    report['cases'].append(dict(core=lang,scenario=mode,status='PASS',observation=json.loads(proc.stdout)))
        report['status']='PASS'
    except Exception:
        report['status']='FAIL'
        raise
    finally:(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: 16 core processes; controlled Source only; full conformance unestablished')
if __name__=='__main__':main()
