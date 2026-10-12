"""Observe 23 A2A call contracts without claiming signed transport conformance."""
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
                                fixtures as card_fixtures, run_native as run_cards)
from current_spec_catalog import load, require, sha

FIXTURE_PATH='vectors/0.10.0/a2a-call-observations.json'
FIXTURE_SHA256='2404b77b46c51327bb36b352a66fe0c334e4d600a6b5e9cb70afc531113e089d'
STRING_LISTS=('errors','replies_hex','payloads_hex','handler_payloads_hex','targets','recipients','versions','extensions','fixture_headers')
COUNTERS=('dispatch_count','owner_calls','final_checks')
UNSUPPORTED={'a2ab-01-bare-jsonrpc-body','a2ab-04-server-grpc-downgrade','a2ab-04-server-0-3-downgrade'}


def input_bytes(case,mode):
    return canonical({'mode':mode,'fixture':case['input']})


def fixtures(root=ROOT):
    raw=(root/FIXTURE_PATH).read_bytes();require(sha(raw)==FIXTURE_SHA256,'call fixture drift')
    suite=load(raw)
    require(suite['spec_revision']==SPEC_REVISION and suite['adk_revision']==ADK_REVISION
            and suite['scope']=='fixture-owner-library-only','call fixture identity')
    old={c['id'] for c in card_fixtures(root)}
    needed={c['id'] for c in inventory(root)['cases'] if c['rule_id'].startswith('A2AB')}-old
    rows=suite['cases'];require(type(rows) is list and len(rows)==23
                and {c['id'] for c in rows}==needed,'complete remaining 23 contracts')
    require({c['id'] for c in rows if c['execution']=='unsupported'}==UNSUPPORTED
            and all(c['reason'] and c['input'] is None and c['expected'] is None
                    for c in rows if c['id'] in UNSUPPORTED),'unsupported ingress contract')
    result=[]
    for c in rows:
        if c['id'] in UNSUPPORTED:result.append(c);continue
        require(c['execution']=='policy' and c['coverage']=='partial'
                and c['scope']=='fixture-owner-library-only' and set(c['expected'])=={'direct','tls'},
                'policy-only observation contract')
        result.append({**c,'input_sha256':sha(input_bytes(c,'tls'))})
    return result


def assess(observations,root=ROOT):
    report=inventory(root);expected={c['id']:c for c in fixtures(root)};observed={}
    require(type(observations) is list and len(observations)<=20,'bounded policy observations')
    for row in observations:
        require(type(row) is dict and set(row)=={'id','mode','input_sha256','actual'}
                and type(row['id']) is str and row['id'] in expected and row['id'] not in observed
                and row['id'] not in UNSUPPORTED and row['mode'] in ('direct','tls'), 'closed policy observation')
        c=expected[row['id']];require(row['input_sha256']==sha(input_bytes(c,row['mode'])),'policy input hash')
        value=row['actual'];want=c['expected'][row['mode']]
        require(type(value) is dict and set(value)==set(want)
                and all(type(value[k]) is int and 0<=value[k]<=2 for k in COUNTERS)
                and all(type(value[k]) is list and len(value[k])<=2 and all(type(x) is str for x in value[k]) for k in STRING_LISTS)
                and type(value['http_statuses']) is list and len(value['http_statuses'])<=2
                and all(type(x) is int and x in (200,403) for x in value['http_statuses']), 'typed policy output')
        observed[row['id']]='PARTIAL' if value==want else 'FAIL'
    for c in report['cases']:
        if c['id'] in UNSUPPORTED:
            c.update(status='UNSUPPORTED',unsupported_reason=expected[c['id']]['reason'],
                     unsupported_component='inspector-production-ingress-observer')
        else:
            c['status']=observed.get(c['id'],'NOT_RUN')
            if c['id'] in expected:c['coverage_notes']=expected[c['id']]['coverage_notes']
    report.update(kind='a2a-call-library-observation',evidence_kind='reported-library-output',
                  subject={'repository':'SAGE-X-project/sage-adk','revision':ADK_REVISION},
                  scope={'policy':'FIXTURE_OWNER_LIBRARY_ONLY','signed_carriage':'NOT_RUN',
                         'public_ingress':'UNSUPPORTED','deployed_registry':'NOT_BOUND','full_conformance':'NOT_ESTABLISHED'},
                  fixture_sha256=FIXTURE_SHA256,observations=observations,
                  status_counts=dict(Counter(c['status'] for c in report['cases'])))
    return report


def observer_sources(root):
    return {p:sha((root/p).read_bytes()) for p in ('scripts/a2a_call_observation.py',
              'scripts/a2a_card_observation.py','scripts/a2a_did_catalog.py','scripts/current_spec_catalog.py')}


def run_native(go,root=ROOT):
    observer=observer_sources(root);directory=root/'adapters/a2a-call';cases=fixtures(root)
    env=os.environ.copy();env.update(GOTOOLCHAIN='local',GOWORK='off',GOFLAGS='-mod=readonly',GOPROXY='off',CGO_ENABLED='0')
    compiler=execute([go,'version'],directory,env).stdout.decode().strip()
    require(bool(re.fullmatch(r'go version go1\.26\.8 (darwin|linux)/(arm64|amd64)',compiler)),'required Go compiler')
    modules=module_info(go,directory,env)
    source=compiler_inputs(go,directory,env)
    require(set(source)=={'main.go','go.mod','go.sum'},'complete adapter source')
    observations=[];raw_trace=[]
    with tempfile.TemporaryDirectory(prefix='sage-call-inspection-') as tmp:
        binary=Path(tmp)/'call-observer';execute([go,'build','-trimpath','-o',str(binary),'.'],directory,env)
        digest=sha(binary.read_bytes())
        for c in cases:
            if c['execution']=='unsupported':continue
            raw=input_bytes(c,'tls')
            done=subprocess.run([str(binary)],input=raw,capture_output=True,timeout=20,env=env,check=True)
            require(len(done.stdout)<=65536 and not done.stderr,'bounded clean policy output')
            observations.append({'id':c['id'],'mode':'tls','input_sha256':sha(raw),'actual':load(done.stdout)})
            raw_trace.append({'id':c['id'],'stdout_hex':done.stdout.hex(),'stdout_sha256':sha(done.stdout)})
        require(digest==sha(binary.read_bytes()),'adapter executable changed')
    require(source==compiler_inputs(go,directory,env)
            and modules==module_info(go,directory,env),'build inputs changed')
    report=assess(observations,root);require(observer==observer_sources(root),'observer source changed')
    report.update(evidence_kind='inspector-launched-native-policy-processes',
                  observer={'repository':'SAGE-X-project/sage-inspector',
                            'revision':execute(['git','rev-parse','HEAD'],root,env).stdout.decode().strip(),
                            'source_sha256':observer},
                  execution={'compiler':compiler,'adapter_sha256':digest,'adapter_source_sha256':source,
                             'modules':modules,'process_count':20,'runtime':'owned-loopback-TLS-policy-fixture',
                             'logical_target_mapping':'fixture-only-not-production-TLS-identity','raw_trace':raw_trace})
    return report


def combine(cards,calls):
    require(cards['spec_revision']==calls['spec_revision']==SPEC_REVISION
            and cards['subject']==calls['subject'] and cards['conformance']==calls['conformance']=='NOT_ESTABLISHED',
            'combined observation identity')
    known={c['id'] for c in inventory()['cases']}
    require({c['id'] for c in cards['cases']}=={c['id'] for c in calls['cases']}==known
            and len(cards['cases'])==len(calls['cases'])==583,'complete combined inventory')
    rows={c['id']:dict(c) for c in cards['cases']}
    for c in calls['cases']:
        require(c['status'] in ('NOT_RUN','PARTIAL','FAIL','UNSUPPORTED') and rows[c['id']]['status'] in ('NOT_RUN','PARTIAL','FAIL'), 'no whole-case PASS transfer')
        if c['status']!='NOT_RUN':
            require(rows[c['id']]['status']=='NOT_RUN','overlapping evidence domains');rows[c['id']]=dict(c)
    return {'schema_version':1,'kind':'a2a-library-observations','spec_revision':SPEC_REVISION,
            'subject':calls['subject'],'conformance':'NOT_ESTABLISHED','scope':calls['scope'],
            'cases':list(rows.values()),'status_counts':dict(Counter(c['status'] for c in rows.values())),
            'components':{'cards':cards,'calls':calls}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',action='store_true');parser.add_argument('--include-cards',action='store_true')
    parser.add_argument('--go',default='go');parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        require(not args.include_cards or args.native,'combined native report requires native execution')
        report=run_native(args.go) if args.native else assess([])
        if args.include_cards:report=combine(run_cards(args.go),report)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
        require(not report['status_counts'].get('FAIL',0),'actual policy mismatch')
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:
        parser.exit(1,'Call observation FAIL: '+str(e)+'\n')
    print('Call observation: '+str(report['status_counts'])+'; signed carriage NOT_RUN')

if __name__=='__main__':main()
