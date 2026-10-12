"""Observe exact registry service-type eligibility with independently signed cards."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from a2a_did_catalog import ROOT, SPEC_REVISION, inventory
from a2a_card_observation import (ADK_REVISION, canonical, execute, module_info, compiler_inputs,
                                  run_native as run_cards)
from a2a_call_observation import combine as combine_calls, run_native as run_calls
from current_spec_catalog import load, require, sha

FIXTURE_PATH='vectors/0.10.0/a2a-service-type-observations.json'
FIXTURE_SHA256='b032684c4a14a421b0232a76a5bfb7eb87186cb76626f1c61d85cd30cf287848'
IDS={'TABLE-08-P','TABLE-08-N01'}


def fixtures(root=ROOT):
    raw=(root/FIXTURE_PATH).read_bytes();require(sha(raw)==FIXTURE_SHA256,'service type fixture drift')
    suite=load(raw);rows=suite['cases']
    needed={c['id'] for c in inventory(root)['cases'] if c['rule_id']=='TABLE-08'}
    require(suite['spec_revision']==SPEC_REVISION and suite['subject_revision']==ADK_REVISION
            and suite['scope']=='card-service-type-library-only' and type(rows) is list
            and len(rows)==2 and {c['id'] for c in rows}==needed==IDS,'complete service type fixture identity')
    positive=next(c for c in rows if c['id']=='TABLE-08-P');negative=next(c for c in rows if c['id']=='TABLE-08-N01')
    control=load(canonical(positive['input']));control['record']['service_types']=['a2ainterface']
    require(canonical(control)==canonical(negative['input'])
            and positive['input']['record']['service_types']==['A2AInterface'], 'only service type changes')
    return [{**c,'input_sha256':sha(canonical(c['input']))} for c in rows]


def assess(observations,root=ROOT):
    report=inventory(root);expected={c['id']:c for c in fixtures(root)};seen={}
    require(type(observations) is list and len(observations)<=2,'bounded service observations')
    for row in observations:
        require(type(row) is dict and set(row)=={'id','input_sha256','actual'}
                and type(row['id']) is str and row['id'] in expected and row['id'] not in seen,'closed service observation identity')
        c=expected[row['id']];require(row['input_sha256']==c['input_sha256'],'service input hash')
        value=row['actual'];want=c['expected']
        require(type(value) is dict and set(value)==set(want) and type(value['accepted']) is bool
                and all(type(value[k]) is str for k in ('error','did','version'))
                and type(value['interfaces']) is list and len(value['interfaces'])<=16
                and all(type(x) is str for x in value['interfaces']), 'typed service output')
        seen[row['id']]='PARTIAL' if canonical(value)==canonical(want) else 'FAIL'
    # A standalone generic refusal does not establish a service-type cause.
    # The same card must first pass the exact-type positive control.
    if seen.get('TABLE-08-N01')=='PARTIAL' and seen.get('TABLE-08-P')!='PARTIAL':
        seen['TABLE-08-N01']='NOT_RUN'
    for c in report['cases']:
        c['status']=seen.get(c['id'],'NOT_RUN')
        if c['id'] in expected:c['coverage_notes']=expected[c['id']]['coverage_notes']
    report.update(kind='a2a-service-type-library-observation',evidence_kind='reported-library-output',
                  subject={'repository':'SAGE-X-project/sage-adk','revision':ADK_REVISION},
                  scope={'service_type':'FIXTURE_SOURCE_LIBRARY_ONLY','protected_transport':'NOT_RUN',
                         'deployed_registry':'NOT_BOUND','full_conformance':'NOT_ESTABLISHED'},
                  fixture_sha256=FIXTURE_SHA256,observations=observations,
                  status_counts=dict(Counter(c['status'] for c in report['cases'])))
    return report


def observer_sources(root):
    return {p:sha((root/p).read_bytes()) for p in ('scripts/a2a_service_type_observation.py','scripts/a2a_call_observation.py',
                                                'scripts/a2a_card_observation.py','scripts/a2a_did_catalog.py','scripts/current_spec_catalog.py')}


def run_native(go,root=ROOT):
    observer=observer_sources(root);directory=root/'adapters/a2a-card';cases=fixtures(root)
    env=os.environ.copy();env.update(GOTOOLCHAIN='local',GOWORK='off',GOFLAGS='-mod=readonly',GOPROXY='off',CGO_ENABLED='0')
    compiler=execute([go,'version'],directory,env).stdout.decode().strip()
    require(re.fullmatch(r'go version go1\.26\.8 (darwin|linux)/(arm64|amd64)',compiler) is not None,'required Go compiler')
    modules=module_info(go,directory,env);source=compiler_inputs(go,directory,env)
    require(set(source)=={'main.go','go.mod','go.sum'},'complete service adapter source')
    observations=[];raw_trace=[]
    with tempfile.TemporaryDirectory(prefix='sage-service-inspection-') as temporary:
        binary=Path(temporary)/'service-observer';execute([go,'build','-trimpath','-o',str(binary),'.'],directory,env);digest=sha(binary.read_bytes())
        for c in cases:
            raw=canonical(c['input']);done=subprocess.run([str(binary)],input=raw,capture_output=True,timeout=15,check=True,env=env)
            require(len(done.stdout)<=65536 and not done.stderr,'bounded clean service output')
            observations.append({'id':c['id'],'input_sha256':sha(raw),'actual':load(done.stdout)})
            raw_trace.append({'id':c['id'],'stdout_hex':done.stdout.hex(),'stdout_sha256':sha(done.stdout)})
        require(digest==sha(binary.read_bytes()),'service executable changed')
    require(source==compiler_inputs(go,directory,env) and modules==module_info(go,directory,env),'service build inputs changed')
    report=assess(observations,root);require(observer==observer_sources(root),'observer source changed')
    report.update(evidence_kind='inspector-launched-native-service-type-processes',
                  observer={'repository':'SAGE-X-project/sage-inspector','revision':execute(['git','rev-parse','HEAD'],root,env).stdout.decode().strip(),'source_sha256':observer},
                  execution={'compiler':compiler,'adapter_sha256':digest,'adapter_source_sha256':source,
                             'modules':modules,'process_count':2,'raw_trace':raw_trace})
    return report


def combine(a2a,services):
    require(a2a['spec_revision']==services['spec_revision']==SPEC_REVISION and a2a['subject']==services['subject']
            and a2a['conformance']==services['conformance']=='NOT_ESTABLISHED','combined service observation identity')
    known={c['id'] for c in inventory()['cases']}
    require(len(a2a['cases'])==len(services['cases'])==583
            and {c['id'] for c in a2a['cases']}=={c['id'] for c in services['cases']}==known,'complete combined service inventory')
    require(all(c['status'] in ('NOT_RUN','PARTIAL','FAIL','UNSUPPORTED') for c in a2a['cases']), 'no whole-case A2A PASS transfer')
    rows={c['id']:dict(c) for c in a2a['cases']}
    for c in services['cases']:
        require(c['status'] in ('NOT_RUN','PARTIAL','FAIL'),'no whole-case service PASS transfer')
        if c['status']!='NOT_RUN':
            require(c['id'] in IDS and rows[c['id']]['status']=='NOT_RUN','service evidence domain overlap');rows[c['id']]=dict(c)
    return {'schema_version':1,'kind':'a2a-and-service-type-library-observations','spec_revision':SPEC_REVISION,
            'subject':a2a['subject'],'conformance':'NOT_ESTABLISHED','scope':a2a['scope'],
            'cases':list(rows.values()),'status_counts':dict(Counter(c['status'] for c in rows.values())),
            'components':{'a2a':a2a,'service_types':services}}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--native',action='store_true')
    parser.add_argument('--include-a2a',action='store_true');parser.add_argument('--go',default='go');parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        require(not args.include_a2a or args.native,'combined service report requires actual native execution')
        report=run_native(args.go) if args.native else assess([])
        if args.include_a2a:report=combine(combine_calls(run_cards(args.go),run_calls(args.go)),report)
        args.output.write_text(json.dumps(report,indent=2)+'\n');require(not report['status_counts'].get('FAIL',0),'service eligibility mismatch')
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:parser.exit(1,'Service observation FAIL: '+str(e)+'\n')
    print('Service observation: '+str(report['status_counts'])+'; full conformance NOT_ESTABLISHED')

if __name__=='__main__':main()
