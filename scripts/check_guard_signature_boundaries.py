"""Actual Guard primitives only; no MCP setup, dispatch or host protection claim."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from inspect_guard_binding import load, require
from test_record010_adapters import PINS
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'vectors/0.10.0/guard-signature-boundaries.json'
FIXTURE_SHA = 'b95708140c324763b3acf73afa763362a8b70afa812f729c8ac38e58dc71dbcc'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixtures():
    raw = FIXTURE.read_bytes()
    require(sha(raw) == FIXTURE_SHA, 'fixture identity')
    return load(raw)['cases']


def validate_response(case, response):
    require(set(response) == {'schema_version','case_id','verdict','output'}, 'response schema')
    require(type(response['schema_version']) is int and response['schema_version'] == 1, 'response version')
    require(response['case_id'] == case['id'], 'case correlation')
    require(response['verdict'] == case['expected'], 'wrong core verdict')
    expected = {'valid': True} if case['expected'] == 'ACCEPT' else {}
    require(response['output'] == expected, 'unexpected core output')
    if case['expected'] == 'ACCEPT':
        require(type(response['output']['valid']) is bool, 'nonboolean validity')


def audit():
    fixtures()
    p = subprocess.run(['node', str(ROOT/'scripts/audit_guard_signatures.js'), str(FIXTURE)], capture_output=True, text=True, timeout=20)
    require(p.returncode == 0, 'independent signature audit: ' + p.stderr)
    result = load(p.stdout)
    require(result == {'cases':10,'valid':8,'invalid':2}, 'signature audit counts')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('go','rust','go-root','rust-root','output'):
        parser.add_argument('--'+key, required=True, type=Path)
    a = parser.parse_args();out=a.output.resolve()
    require(not out.exists() and not out.is_relative_to(ROOT), 'new output outside repository required')
    rows=fixtures();checked=audit()
    for name,pin in PINS.items():
        source=getattr(a,name+'_root').resolve()
        require(subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()==pin,'core revision')
        require(not subprocess.check_output(['git','diff','HEAD','--name-only'],cwd=source,text=True).strip(),'tracked core edits')
    out.mkdir(parents=True,exist_ok=False)
    report=dict(kind='guard-signature-boundaries',status='RUNNING',actual_core_execution=False,
                conformance='NOT_ESTABLISHED',mcp_protocol_execution='NOT_RUN',proposal_cases={'NOT_RUN':71},
                lifecycle={'NOT_RUN':37},fixture_sha256=FIXTURE_SHA,signature_audit=checked,
                inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                subjects={},results=[],limitations=['Only existing intent/result primitive APIs and test Authority seams.',
                'P-256 signatures independently valid; the Ed25519-only Authority API does not model an active P-256 registry key.',
                'No secp256k1, outer/handshake role, MCP initialization, dispatch or production registry verification.'])
    try:
        for name,pin in PINS.items():
            adapter=getattr(a,name).resolve(strict=True)
            report['subjects'][name]=dict(revision=pin,adapter_sha256=sha(adapter.read_bytes()))
            for c in rows:
                q=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',case_id=c['id'],operation=c['operation'],input=c['input'])
                stem=name+'-'+c['id']
                (out/(stem+'.request.json')).write_text(json.dumps(q)+'\n')
                report['actual_core_execution']=True
                p=subprocess.run([str(adapter)],input=json.dumps(q),capture_output=True,text=True,timeout=10)
                (out/(stem+'.stdout')).write_text(p.stdout)
                (out/(stem+'.stderr')).write_text(p.stderr)
                require(p.returncode==0,'adapter failed: '+stem)
                response=load(p.stdout);validate_response(c,response)
                report['results'].append(dict(subject=name,id=c['id'],status='PASS',verdict=response['verdict'],response_sha256=sha(p.stdout.encode())))
        report['status']='PASS'
    except (OSError,ValueError,KeyError,subprocess.TimeoutExpired) as error:
        report.update(status='FAIL',error=str(error))
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(report['status']+': Guard signature primitives; MCP cases remain NOT_RUN')
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
