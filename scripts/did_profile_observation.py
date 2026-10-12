"""Observe adopted DID projections and resolution, never infer message authority."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from a2a_did_catalog import ROOT, SPEC_REVISION, inventory
from a2a_card_observation import canonical, execute, compiler_inputs
from current_spec_catalog import load, require, sha

FIXTURE_PATH='vectors/0.10.0/did-profile-observations.json'
FIXTURE_SHA256='299a25a3cee82880490ea46fb61cc15371e8175961fd3c8c4f725ea0f21cfbbf'
MODULES={
 'github.com/sage-x-project/did-go':'v0.0.0-20261012015322-ed54c505eafe',
 'github.com/sage-x-project/did-go/advanced/sage':'v0.0.0-20261012020818-2ef282b40ccf'}
UNSUPPORTED={'didp-03-two-observations','didp-04-peer-document-ignored','didp-04-received-alias'}
KNOWN_GAPS={'didp-05-unsupported-accept','didp-02-json-envelope'}


def fixtures(root=ROOT):
    raw=(root/FIXTURE_PATH).read_bytes();require(sha(raw)==FIXTURE_SHA256,'DID fixture drift')
    suite=load(raw);rows=suite['cases']
    known={c['id']:c for c in inventory(root)['cases'] if c['rule_id'].startswith('DIDP-')}
    require(suite['spec_revision']==SPEC_REVISION and suite['subject_revision']=='2ef282b40ccf'
            and suite['scope']=='did-projection-resolution-fixture-source'
            and type(rows) is list and len(rows)==28 and {c['id'] for c in rows}==set(known), 'complete DID fixture identity')
    require({c['id'] for c in rows if c['execution']=='unsupported'}==UNSUPPORTED,'unsupported DID scope')
    result=[]
    for c in rows:
        require(c['rule_id']==known[c['id']]['rule_id'],'DID rule identity')
        if c['id'] in UNSUPPORTED:
            require(c['input'] is None and c['expected'] is None and c['reason'], 'unsupported contract')
            result.append(c)
        else:
            require(c['execution']=='native' and c['coverage']=='partial' and c['coverage_notes'], 'partial DID contract')
            result.append({**c,'input_sha256':sha(canonical(c['input']))})
    return result


def checked_actual(value,count):
    require(type(value) is dict and set(value)=={'source_calls','network_attempts','responses'}
            and all(type(value[k]) is int and 0<=value[k]<=2 for k in ('source_calls','network_attempts'))
            and type(value['responses']) is list and len(value['responses'])==count, 'typed DID output')
    result=[]
    for row in value['responses']:
        require(type(row) is dict and set(row)=={'status','content_type','body_hex','sage_code','problem_type'}
                and type(row['status']) is int and 100<=row['status']<=599
                and all(type(row[k]) is str and len(row[k])<=524288 for k in ('content_type','body_hex','sage_code','problem_type'))
                and re.fullmatch('(?:[0-9a-f]{2})*',row['body_hex']) is not None,'closed DID response')
        raw=bytes.fromhex(row['body_hex']);body=load(raw) if raw else None
        require(body is None or type(body) is dict,'DID object body')
        result.append({k:row[k] for k in ('status','content_type','sage_code','problem_type')}|{'body':body})
    return {'source_calls':value['source_calls'],'network_attempts':value['network_attempts'],'responses':result}


def matches(actual,want,interface):
    if actual['source_calls']!=want['source_calls'] or actual['network_attempts']!=want['network_attempts']:return False
    for got,expected in zip(actual['responses'],want['responses']):
        if any(got[k]!=expected[k] for k in ('status','content_type','sage_code','problem_type')):return False
        if expected['body'] is not None:
            if canonical(got['body'])!=canonical(expected['body']):return False
        elif interface=='sage-api':
            if got['body'] is not None:return False
        else:
            problem=got['body']
            if type(problem) is not dict or not {'type','title','status'}<=set(problem) or not set(problem)<={'type','title','status','detail','sageCode'}:return False
            if (problem.get('type')!=expected['problem_type'] or problem.get('sageCode')!=expected['sage_code']
                    or type(problem.get('status')) is not int or problem['status']!=expected['status']
                    or type(problem.get('title')) is not str or not problem['title']
                    or ('detail' in problem and type(problem['detail']) is not str)):return False
    return True


def assess(observations,root=ROOT):
    expected={c['id']:c for c in fixtures(root)};report=inventory(root);seen={};require(type(observations) is list and len(observations)<=25,'bounded DID observations')
    for row in observations:
        require(type(row) is dict and set(row)=={'id','input_sha256','actual'} and type(row['id']) is str
                and row['id'] in expected and row['id'] not in seen and row['id'] not in UNSUPPORTED,'closed DID observation identity')
        c=expected[row['id']];require(row['input_sha256']==c['input_sha256'],'DID input hash')
        actual=checked_actual(row['actual'],len(c['input']['accepts']))
        seen[row['id']]='PARTIAL' if matches(actual,c['expected'],c['input']['interface']) else 'FAIL'
    for c in report['cases']:
        c['status']=seen.get(c['id'],'NOT_RUN')
        if c['id'] in expected:c['coverage_notes']=expected[c['id']]['coverage_notes']
        if c['id'] in UNSUPPORTED:c.update(status='UNSUPPORTED',unsupported_reason=expected[c['id']]['reason'],unsupported_component='inspector-protected-verifier-or-dual-resolution-observer')
    report.update(kind='did-projection-resolution-observation',evidence_kind='reported-library-output',
                  subject={'repository':'SAGE-X-project/did-go','module_versions':MODULES},
                  scope={'projection':'FIXTURE_SOURCE_LIBRARY_ONLY','sage_http_binding':'NOT_RUN',
                         'did_resolution_http':'OWNED_LOOPBACK_TLS_ONLY','protected_message_authority':'NOT_RUN',
                         'deployed_registry':'NOT_BOUND','full_conformance':'NOT_ESTABLISHED'},
                  fixture_sha256=FIXTURE_SHA256,observations=observations,
                  status_counts=dict(Counter(c['status'] for c in report['cases'])))
    return report


def known_gap_only(report):
    failures={c['id'] for c in report['cases'] if c['status']=='FAIL'}
    if failures!=KNOWN_GAPS:return False
    contracts={c['id']:c for c in fixtures()}
    for id in KNOWN_GAPS:
        rows=[r for r in report['observations'] if r['id']==id]
        if len(rows)!=1:return False
        c=contracts[id];actual=checked_actual(rows[0]['actual'],1)
        alternate=json.loads(json.dumps(c['expected']))
        if id=='didp-02-json-envelope':
            del alternate['responses'][0]['body']['didDocumentMetadata']['deactivated']
        else:
            alternate['responses'][0]['sage_code']=''
            body=actual['responses'][0]['body']
            if type(body) is not dict or 'sageCode' in body:return False
            actual=json.loads(json.dumps(actual));actual['responses'][0]['body']['sageCode']=''
        if not matches(actual,alternate,c['input']['interface']):return False
    return True


def module_info(go,directory,env):
    result=[]
    for path,version in MODULES.items():
        value=load(execute([go,'list','-m','-json',path],directory,env).stdout)
        require(value.get('Path')==path and value.get('Version')==version and 'Replace' not in value
                and all(re.fullmatch('h1:[A-Za-z0-9+/]{43}=',value.get(k,'')) for k in ('Sum','GoModSum')), 'pinned DID module')
        result.append({k:value[k] for k in ('Path','Version','Sum','GoModSum')})
    require(execute([go,'mod','verify'],directory,env).stdout==b'all modules verified\n','verified DID module cache')
    return result


def observer_sources(root):
    return {p:sha((root/p).read_bytes()) for p in ('scripts/did_profile_observation.py','scripts/a2a_card_observation.py','scripts/a2a_did_catalog.py','scripts/current_spec_catalog.py')}


def run_native(go,root=ROOT):
    observer=observer_sources(root);directory=root/'adapters/did-profile';cases=fixtures(root)
    env=os.environ.copy();env.update(GOTOOLCHAIN='local',GOWORK='off',GOFLAGS='-mod=readonly',GOPROXY='off',CGO_ENABLED='0')
    compiler=execute([go,'version'],directory,env).stdout.decode().strip()
    require(re.fullmatch(r'go version go1\.26\.8 (darwin|linux)/(arm64|amd64)',compiler) is not None,'required Go compiler')
    modules=module_info(go,directory,env);source=compiler_inputs(go,directory,env)
    require(set(source)=={'main.go','go.mod','go.sum'},'complete DID adapter source')
    observations=[];raw_trace=[]
    with tempfile.TemporaryDirectory(prefix='sage-did-inspection-') as tmp:
        binary=Path(tmp)/'did-observer';execute([go,'build','-trimpath','-o',str(binary),'.'],directory,env);digest=sha(binary.read_bytes())
        for c in cases:
            if c['id'] in UNSUPPORTED:continue
            raw=canonical(c['input']);done=subprocess.run([str(binary)],input=raw,capture_output=True,timeout=20,env=env,check=True)
            require(len(done.stdout)<=2*1024*1024 and not done.stderr,'bounded clean DID output')
            observations.append({'id':c['id'],'input_sha256':sha(raw),'actual':load(done.stdout)})
            raw_trace.append({'id':c['id'],'stdout_hex':done.stdout.hex(),'stdout_sha256':sha(done.stdout)})
        require(digest==sha(binary.read_bytes()),'DID executable changed')
    require(source==compiler_inputs(go,directory,env) and modules==module_info(go,directory,env),'DID build inputs changed')
    report=assess(observations,root);require(observer==observer_sources(root),'observer source changed')
    report.update(evidence_kind='inspector-launched-native-DID-processes',
                  observer={'repository':'SAGE-X-project/sage-inspector','revision':execute(['git','rev-parse','HEAD'],root,env).stdout.decode().strip(),'source_sha256':observer},
                  execution={'compiler':compiler,'adapter_sha256':digest,'adapter_source_sha256':source,'modules':modules,
                             'process_count':25,'runtime':'library-api-and-owned-loopback-TLS','raw_trace':raw_trace})
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--native',action='store_true')
    parser.add_argument('--go',default='go');parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--record-known-gap',action='store_true',help='Record the two exact pinned missing metadata members as FAIL; permit these known findings only.')
    args=parser.parse_args()
    try:
        require(not args.record_known_gap or args.native,'known-gap recording requires actual execution')
        report=run_native(args.go) if args.native else assess([]);args.output.write_text(json.dumps(report,indent=2)+'\n')
        require(not report['status_counts'].get('FAIL',0) or (args.record_known_gap and known_gap_only(report)), 'DID conformance finding; report preserves FAIL')
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:parser.exit(1,'DID observation FAIL: '+str(e)+'\n')
    print('DID observation: '+str(report['status_counts'])+'; full conformance NOT_ESTABLISHED')

if __name__=='__main__':main()
