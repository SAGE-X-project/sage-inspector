"""Prepare host coverage, or execute probes through an explicitly configured host adapter."""
import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path
from inspect_guard import validate_scenario
from integrate_evidence import decode, same, require

ROOT=Path(__file__).resolve().parents[1]

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def inventory(root):
    base=root/'vectors/0.10.0'
    raw=(base/'host-manifest.json').read_bytes();manifest=decode(raw)
    require(manifest['schema_version']==1 and manifest['protocol_version']=='0.10.0','manifest version')
    entries=manifest['scenarios']
    require(len(entries)==8 and len({e['id'] for e in entries})==8,'host inventory incomplete')
    files={p.name for p in (base/'host-scenarios').glob('*.json')}
    require({e['file'] for e in entries}==files,'host scenario membership changed')
    result=[]
    for entry in entries:
        path=(base/'host-scenarios'/entry['file']).resolve()
        require(path.parent==(base/'host-scenarios').resolve(),'fixture path escape')
        raw_fixture=path.read_bytes();fixture=decode(raw_fixture)
        require(sha(raw_fixture)==entry['sha256'] and fixture['id']==entry['id'] and len(fixture['steps'])==entry['steps'],'host fixture changed')
        result.append((entry,path,raw_fixture))
    return sha(raw),result

def binding_details(path, adapter):
    raw=path.read_bytes();binding=decode(raw)
    for field in ('name','version','revision','isolation','witness_boundary'):
        require(isinstance(binding.get(field),str) and binding[field].strip(),'missing host '+field)
    identities={}
    for field in ('host_executable','host_configuration','witness_executable'):
        require(Path(binding[field]).is_absolute(),'binding file path must be absolute')
        file=Path(binding[field]).resolve(strict=True)
        identities[field]=dict(path=str(file),sha256=sha(file.read_bytes()))
    require(identities['witness_executable']['path']!=str(adapter),'witness must be outside the subject adapter')
    return dict(declaration=binding,declaration_sha256=sha(raw),files=identities,
                limitation='Operator declaration and file identity, not automatic proof of runtime isolation or witness trust.')

def inspect(root,out,runner=None,adapter=None,binding=None):
    require(not out.exists(),'output directory exists')
    manifest_hash,entries=inventory(root)
    require(all(v is None for v in (runner,adapter,binding)) or all(v is not None for v in (runner,adapter,binding)), 'runner, adapter and binding must be supplied together')
    details=binding_details(binding,adapter) if binding else None
    adapter_hash=sha(adapter.read_bytes()) if adapter else None
    out.mkdir(parents=True)
    report=dict(schema_version=1,protocol_version='0.10.0',scope='Host deployment probes; no whole-host or complete isolation certification.',
                conformance='NOT_ESTABLISHED',status='INCOMPLETE',manifest_sha256=manifest_hash,binding=details,
                adapter_sha256=adapter_hash,runner_sha256=sha(runner.read_bytes()) if runner else None,
                environment=platform.platform(),scenarios=[],evidence_files={})
    for entry,path,raw in entries:
        row=dict(id=entry['id'],fixture_sha256=entry['sha256'],rule_ids=entry['rule_ids'],steps=entry['steps'],status='NOT_RUN',observed_effects=None,reason='No pinned host adapter and external witness binding supplied.')
        if adapter:
            require(sha(adapter.read_bytes())==adapter_hash,'adapter changed')
            require(binding_details(binding,adapter)==details,'host binding changed')
            target=out/path.name
            with target.open('xb') as stream:
                result=subprocess.run([str(runner),'-scenario',str(path),'-adapter',str(adapter),'-subject',details['declaration']['name'],'-revision',details['declaration']['revision']],stdout=stream,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,timeout=90,check=False)
            require(result.returncode in (0,1,3),'host runner failed')
            observed=decode(target.read_bytes());validate_scenario(raw,observed)
            require(result.returncode=={'PASS':0,'FAIL':1,'INCOMPLETE':3}[observed['status']],'runner exit mismatch')
            require(observed['subject']==dict(name=details['declaration']['name'],revision=details['declaration']['revision'],kind='external',executable_sha256=adapter_hash),'host subject mismatch')
            fixture=decode(raw)
            require(same(observed['sources'],fixture['sources']) and observed['environment'] and observed['created'],'missing host execution provenance')
            for step,actual in zip(fixture['steps'],observed['steps']):
                if actual['status']=='PASS':
                    require(same(actual['actual']['effects'],step['effects']) and same(actual['actual']['output'],step['expected']['output']),'false host PASS')
            require(binding_details(binding,adapter)==details and sha(adapter.read_bytes())==adapter_hash and sha(runner.read_bytes())==report['runner_sha256'],'host binding or executable changed during probe')
            row.update(status=observed['status'],reason=observed.get('reason',''),observed_effects=[dict(step_id=s['step_id'],status=s['status'],effects=(s.get('actual') or {}).get('effects')) for s in observed['steps']],report=target.name)
            report['evidence_files'][target.name]=sha(target.read_bytes())
        report['scenarios'].append(row)
    if any(s['status']=='FAIL' for s in report['scenarios']):report['status']='FAIL'
    elif all(s['status']=='PASS' for s in report['scenarios']):report['status']='PASS'
    (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',required=True,type=Path)
    for name in ('runner','adapter','binding'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    try:
        report=inspect(ROOT,args.output_dir.resolve(),*(getattr(args,n).resolve(strict=True) if getattr(args,n) else None for n in ('runner','adapter','binding')))
        print(json.dumps({'status':report['status'],'report':str(args.output_dir/'summary.json')}))
        return {'PASS':0,'FAIL':1,'INCOMPLETE':3}[report['status']]
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as error:
        print('Host inspection failed: '+str(error));return 2
if __name__=='__main__':raise SystemExit(main())
