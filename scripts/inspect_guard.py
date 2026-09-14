"""Execute frozen Execution Guard commitments and envelopes and optional real stateful subject bindings."""
import argparse
import collections
import hashlib
import json
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
NAMES=('guard-records',)
STATUSES=('PASS','FAIL','UNSUPPORTED','NOT_RUN')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_report(raw,report):
    suite=json.loads(raw)
    if report['suite_sha256']!=sha(raw) or report['suite_id']!=suite['id'] or report['protocol_version']!='0.10.0' or report['schema_version']!=1:
        raise ValueError('suite/report identity mismatch')
    cases={c['id']:c for c in suite['cases']}
    counts=collections.Counter({s:0 for s in STATUSES})
    seen=set()
    for r in report['results']:
        ident,status=r['case_id'],r['status']
        if ident in seen or ident not in cases or status not in STATUSES:
            raise ValueError('invalid or duplicate result')
        seen.add(ident)
        c=cases[ident]
        if r['operation']!=c['operation'] or r['expected']!=c['expected'] or r['rule_ids']!=c['rule_ids']:
            raise ValueError('case mismatch')
        a=r.get('actual')
        if status in ('PASS','UNSUPPORTED') and (not a or a['case_id']!=ident or a['schema_version']!=1):
            raise ValueError('observation identity mismatch')
        if status=='PASS' and (a['verdict']!=c['expected']['verdict'] or a['output']!=c['expected']['output']):
            raise ValueError('false PASS')
        if status=='UNSUPPORTED' and a['verdict']!='UNSUPPORTED':
            raise ValueError('false unsupported observation')
        counts[status]+=1
    inferred='FAIL' if counts['FAIL'] else 'INCOMPLETE' if counts['UNSUPPORTED'] or counts['NOT_RUN'] else 'PASS'
    if set(cases)!=seen or dict(counts)!=report['counts'] or report['status']!=inferred:
        raise ValueError('incomplete counts/status')
    return counts


def validate_scenario(raw, report):
    fixture=json.loads(raw)
    if report['fixture_sha256']!=sha(raw) or report['case_id']!=fixture['id'] or report['schema_version']!=2 or report['protocol_version']!='0.10.0' or report['profile']!='stateful-scenario':
        raise ValueError('scenario identity mismatch')
    if len(report['steps'])!=len(fixture['steps']):
        raise ValueError('scenario membership mismatch')
    stopped=False;failed=False;incomplete=False
    for expected,actual in zip(fixture['steps'], report['steps']):
        status=actual['status']
        if actual['step_id']!=expected['id'] or actual['input']!=expected['input'] or actual['expected']!=expected['expected'] or actual['expected_effects']!=expected['effects']:
            raise ValueError('scenario step mismatch')
        if status not in STATUSES or (stopped and status!='NOT_RUN'):
            raise ValueError('invalid scenario progression')
        observation=actual.get('actual')
        if status in ('PASS','UNSUPPORTED'):
            if not observation or observation['schema_version']!=2 or observation['case_id']!=fixture['id'] or observation['step_id']!=expected['id']:
                raise ValueError('scenario observation identity mismatch')
            if status=='PASS' and (observation['verdict']!=expected['expected']['verdict'] or observation['output']!=expected['expected']['output'] or observation['effects']!=expected['effects']):
                raise ValueError('false scenario PASS')
            if status=='UNSUPPORTED' and observation['verdict']!='UNSUPPORTED':
                raise ValueError('false scenario unsupported')
        if status!='PASS': stopped=True
        failed |= status=='FAIL'
        incomplete |= status in ('UNSUPPORTED','NOT_RUN')
    inferred='FAIL' if failed else 'INCOMPLETE' if incomplete else 'PASS'
    # Process-exit/trailing-output failures can occur after every step passed.
    if report['status']!=inferred and not (report['status']=='FAIL' and report.get('reason')):
        raise ValueError('scenario aggregate mismatch')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for field in ('runner','adapter','subject','revision','output-dir'):
        p.add_argument('--'+field,required=True)
    p.add_argument('--scenario-runner')
    p.add_argument('--state-adapter')
    args=p.parse_args()
    if bool(args.scenario_runner)!=bool(args.state_adapter):
        p.error('scenario runner and state adapter must be supplied together')
    try:
        runner=Path(args.runner).resolve(strict=True);adapter=Path(args.adapter).resolve(strict=True)
        state_runner=Path(args.scenario_runner).resolve(strict=True) if args.scenario_runner else None
        state_adapter=Path(args.state_adapter).resolve(strict=True) if args.state_adapter else None
        out=Path(args.output_dir).resolve();out.mkdir(parents=True,exist_ok=False)
    except OSError as e:
        print(str(e));return 2
    try:
        closure_raw=(ROOT/'vectors/0.10.0/guard-closure-links.json').read_bytes()
        closure=json.loads(closure_raw)
        for item in closure['links']:
            file=(ROOT/'vectors/0.10.0'/item['file']).resolve()
            if not file.is_relative_to((ROOT/'vectors/0.10.0').resolve()): raise ValueError('closure path escapes fixture root')
            raw=file.read_bytes()
            if sha(raw)!=item['sha256']: raise ValueError('closure fixture changed')
            fixture=json.loads(raw)
            if fixture['id']!=item['id']: raise ValueError('closure identity changed')
        reports=[];counts=collections.Counter({s:0 for s in STATUSES});evidence={};rules={};subject=None
        for name in NAMES:
            file=ROOT/'vectors/0.10.0'/f'{name}.json';raw=file.read_bytes();output=out/f'{name}.json'
            r=subprocess.run([str(runner),'-suite',str(file),'-adapter',str(adapter),'-subject',args.subject,'-revision',args.revision,'-report',str(output)],
                             stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=len(json.loads(raw)['cases'])*5+30,check=False)
            if r.returncode not in (0,1,3):
                raise ValueError('primitive runner failed: '+name)
            report=json.loads(output.read_text());counts.update(validate_report(raw,report))
            if r.returncode!={'PASS':0,'FAIL':1,'INCOMPLETE':3}[report['status']]:
                raise ValueError('runner exit mismatch')
            if subject is not None and subject!=report['subject']:
                raise ValueError('subject changed between suites')
            subject=report['subject']
            if subject['name']!=args.subject or subject['revision']!=args.revision: raise ValueError('primitive subject mismatch')
            reports.append({'suite_id':report['suite_id'],'suite_sha256':report['suite_sha256'],'status':report['status'],'counts':report['counts']})
            evidence[output.name]=sha(output.read_bytes())
            for item in report['results']:
                for rule in item['rule_ids']:
                    rules.setdefault(rule,[]).append({'suite_id':report['suite_id'],'case_id':item['case_id'],'status':item['status']})
        manifest_raw=(ROOT/'vectors/0.10.0/guard-manifest.json').read_bytes()
        manifest=json.loads(manifest_raw)
        if manifest['records_sha256']!=reports[0]['suite_sha256']:
            raise ValueError('manifest record hash mismatch')
        entries={e['id']:e for e in manifest['scenarios']}
        if len(entries)!=37: raise ValueError('manifest membership mismatch')
        scenarios=[]
        state_subject=None
        for file in sorted((ROOT/'vectors/0.10.0/guard-scenarios').glob('*.json')):
            raw=file.read_bytes();fixture=json.loads(raw)
            entry=entries.pop(fixture['id'])
            if entry['file']!=file.name or entry['sha256']!=sha(raw): raise ValueError('manifest scenario mismatch')
            item={'rule_ids':entry['rule_ids'],'id':fixture['id'],'fixture_sha256':sha(raw),'status':'NOT_RUN','steps':len(fixture['steps']),'reason':'No stateful core binding supplied; schema1 adapters are not scenario adapters.'}
            if state_adapter:
                output=out/file.name
                with output.open('wb') as stream:
                    r=subprocess.run([str(state_runner),'-scenario',str(file),'-adapter',str(state_adapter),'-subject',args.subject,'-revision',args.revision],
                                     stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.DEVNULL,timeout=90,check=False)
                if r.returncode not in (0,1,3):
                    raise ValueError('scenario runner failed: '+file.name)
                report=json.loads(output.read_text())
                validate_scenario(raw,report)
                if r.returncode!={'PASS':0,'FAIL':1,'INCOMPLETE':3}[report['status']]:
                    raise ValueError('scenario exit mismatch')
                if report['subject']['name']!=args.subject or report['subject']['revision']!=args.revision:
                    raise ValueError('scenario subject mismatch')
                if state_subject is not None and state_subject!=report['subject']:
                    raise ValueError('state subject changed')
                state_subject=report['subject']
                item.update(status=report['status'],reason=report.get('reason',''),step_statuses=[s['status'] for s in report['steps']])
                evidence[output.name]=sha(output.read_bytes())
            scenarios.append(item)
            for rule in entry['rule_ids']:
                rules.setdefault(rule,[]).append({'scenario_id':item['id'],'status':item['status']})
        if len(scenarios)!=37 or entries:
            raise ValueError('missing lifecycle scenarios')
        status='FAIL' if counts['FAIL'] or any(s['status']=='FAIL' for s in scenarios) else 'INCOMPLETE' if counts['UNSUPPORTED'] or counts['NOT_RUN'] or any(s['status']!='PASS' for s in scenarios) else 'PASS'
        summary=dict(schema_version=1,protocol_version='0.10.0',bundle='guard-inspection',subject=subject,state_subject=state_subject,status=status,
                     closure_links_sha256=sha(closure_raw),closure_links=closure,manifest_sha256=sha(manifest_raw),primitive_counts=dict(counts),suites=reports,rules=rules,scenarios=scenarios,evidence_files=evidence,
                     scope='JCS/signature projections and independent Guard boundary contracts. Stateful dispatch requires actual protected instrumentation. No semantic safety, host isolation or whole-host compromise certification.')
        (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps({'status':status,'counts':dict(counts),'report':str(out/'summary.json')}))
        return {'PASS':0,'FAIL':1,'INCOMPLETE':3}[status]
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as e:
        (out/'summary.json').write_text(json.dumps({'status':'ERROR','reason':str(e)})+'\n')
        print(str(e));return 2


if __name__=='__main__':
    raise SystemExit(main())
