"""Observe pinned ADK card checks; a card is not protected-operation evidence."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from a2a_did_catalog import ROOT, SPEC_REVISION, inventory
from current_spec_catalog import load, require, sha

FIXTURE_PATH='vectors/0.10.0/a2a-card-observations.json'
FIXTURE_SHA256='ff9d09ab9134aa134acff8ffd96466e38126ef0ee5ca320abc32dcc8be4d1448'
ADK_REVISION='904fa9cbe3c4c2dcdabee67b2afd7c9e4b75cf14'
MODULES={
 'github.com/sage-x-project/sage-adk':'v0.0.0-20261012212823-904fa9cbe3c4',
 'github.com/sage-x-project/sage':'v1.5.3-0.20261012104536-4c7bad17ce17',
 'github.com/sage-x-project/did-go':'v0.0.0-20261012015322-ed54c505eafe',
 'github.com/sage-x-project/did-go/advanced/sage':'v0.0.0-20261012020818-2ef282b40ccf'}

def canonical(v):
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def fixtures(root=ROOT):
    raw=(root/FIXTURE_PATH).read_bytes()
    require(sha(raw)==FIXTURE_SHA256,'independent fixture drift')
    suite=load(raw)
    require(suite['spec_revision']==SPEC_REVISION and suite['subject_revision']==ADK_REVISION
            and suite['scope']=='card-library-only' and len(suite['cases'])==41,'fixture identity')
    known={c['id'] for c in inventory(root)['cases']};seen=set();result=[]
    for c in suite['cases']:
        require(c['id'] in known and c['id'] not in seen and c['coverage']=='partial'
                and c['scope']=='card-library-only','fixture scope or duplicate')
        seen.add(c['id']); result.append({**c,'input_sha256':sha(canonical(c['input']))})
    return result


def assess(observations,root=ROOT):
    report=inventory(root);expected={c['id']:c for c in fixtures(root)};observed={}
    require(type(observations) is list and len(observations)<=41,'bounded observations')
    for row in observations:
        require(type(row) is dict and set(row)=={'id','input_sha256','actual'}
                and type(row['id']) is str and row['id'] in expected and row['id'] not in observed,
                'closed observation identity')
        case=expected[row['id']]
        require(row['input_sha256']==case['input_sha256'],'observed input hash')
        value=row['actual'];want=case['expected']
        require(type(value) is dict and set(value)==set(want)
                and type(value['accepted']) is bool
                and all(type(value[k]) is str for k in ('error','did','version'))
                and type(value['interfaces']) is list
                and all(type(x) is str for x in value['interfaces']),'typed card output')
        observed[row['id']]='PARTIAL' if value==want else 'FAIL'
    for case in report['cases']:case['status']=observed.get(case['id'],'NOT_RUN')
    report.update(kind='a2a-card-library-observation',evidence_kind='reported-library-output',
                  scope={'card':'FIXTURE_SOURCE_LIBRARY_ONLY','protected_transport':'NOT_RUN',
                         'deployed_registry':'NOT_BOUND','full_conformance':'NOT_ESTABLISHED'},
                  subject={'repository':'SAGE-X-project/sage-adk','revision':ADK_REVISION},
                  fixture_sha256=FIXTURE_SHA256,observations=observations,
                  status_counts=dict(Counter(c['status'] for c in report['cases'])))
    return report


def execute(command,cwd,env,timeout=120):
    done=subprocess.run(command,cwd=cwd,env=env,capture_output=True,timeout=timeout,check=True)
    require(len(done.stdout)<=4*1024*1024 and len(done.stderr)<=65536,'bounded process output')
    return done


def module_info(go,directory,env):
    result=[]
    for path,version in MODULES.items():
        value=load(execute([go,'list','-m','-json',path],directory,env).stdout)
        require(value.get('Path')==path and value.get('Version')==version and 'Replace' not in value
                and re.fullmatch('h1:[A-Za-z0-9+/]{43}=',value.get('Sum',''))
                and re.fullmatch('h1:[A-Za-z0-9+/]{43}=',value.get('GoModSum','')),'pinned module without replacement')
        result.append({k:value[k] for k in ('Path','Version','Sum','GoModSum')})
    done=execute([go,'mod','verify'],directory,env)
    require(done.stdout==b'all modules verified\n' and not done.stderr,'verified module cache')
    return result


def observer_sources(root):
    return {path:sha((root/path).read_bytes()) for path in
            ('scripts/a2a_card_observation.py','scripts/a2a_did_catalog.py','scripts/current_spec_catalog.py')}


def compiler_inputs(go,directory,env):
    package=load(execute([go,'list','-json','.'],directory,env).stdout)
    require(package.get('GoFiles')==['main.go'] and not package.get('CgoFiles')
            and not package.get('SFiles') and not package.get('SysoFiles'), 'unexpected compiler inputs')
    return {p.name:sha(p.read_bytes()) for p in directory.iterdir() if p.name in ('main.go','go.mod','go.sum')}


def run_native(go,root=ROOT):
    observer=observer_sources(root)
    directory=root/'adapters/a2a-card'
    env=os.environ.copy();env.update(GOTOOLCHAIN='local',GOWORK='off',GOFLAGS='-mod=readonly',GOPROXY='off',CGO_ENABLED='0')
    compiler=execute([go,'version'],directory,env).stdout.decode().strip()
    require(bool(re.fullmatch(r'go version go1\.26\.8 (darwin|linux)/(arm64|amd64)',compiler)),
            'required Go compiler')
    modules=module_info(go,directory,env)
    source=compiler_inputs(go,directory,env)
    require(set(source)=={'main.go','go.mod','go.sum'},'complete adapter source')
    observations=[];raw_trace=[]
    with tempfile.TemporaryDirectory(prefix='sage-card-inspection-') as temporary:
        binary=Path(temporary)/'card-observer'
        execute([go,'build','-trimpath','-o',str(binary),'.'],directory,env)
        digest=sha(binary.read_bytes())
        for c in fixtures(root):
            raw=canonical(c['input'])
            done=subprocess.run([str(binary)],input=raw,capture_output=True,timeout=15,check=True,env=env)
            require(len(done.stdout)<=65536 and not done.stderr,'bounded clean card output')
            actual=load(done.stdout)
            observations.append({'id':c['id'],'input_sha256':sha(raw),'actual':actual})
            raw_trace.append({'id':c['id'],'stdout_hex':done.stdout.hex(),'stdout_sha256':sha(done.stdout)})
        require(digest==sha(binary.read_bytes()),'adapter executable changed')
    require(source==compiler_inputs(go,directory,env)
            and modules==module_info(go,directory,env),'build inputs changed')
    report=assess(observations,root)
    require(observer==observer_sources(root),'observer source changed')
    revision=execute(['git','rev-parse','HEAD'],root,env).stdout.decode().strip()
    report['observer']={'repository':'SAGE-X-project/sage-inspector','revision':revision,
                        'source_sha256':observer}
    report.update(evidence_kind='inspector-launched-native-card-processes',
                  execution={'compiler':compiler,'adapter_sha256':digest,'adapter_source_sha256':source,
                             'modules':modules,'process_count':41,'raw_trace':raw_trace})
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',action='store_true')
    parser.add_argument('--go',default='go')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        report=run_native(args.go) if args.native else assess([])
        args.output.write_text(json.dumps(report,indent=2)+'\n')
        require(not report['status_counts'].get('FAIL',0),'actual card mismatch')
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:
        parser.exit(1,'Card observation FAIL: '+str(e)+'\n')
    print('Card observation: '+str(report['status_counts'])+'; full conformance NOT_ESTABLISHED')

if __name__=='__main__':main()
