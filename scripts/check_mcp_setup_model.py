"""Run a bounded abstract model; no MCP peer, core, tool or attack traffic is invoked."""
import argparse,hashlib,json,subprocess
from pathlib import Path
from mcp_setup_model import explore
from inspect_guard_binding import load,require
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'verification/0.10.0/mcp-setup-proposal'
REVISION='a70784d6c3415b08d344bc7705f738df977ad3f9'
FILES={'README.md','cases.json','review.json','review.md','tool.json','basis.json','verify.py'}

def sha(raw):return hashlib.sha256(raw).hexdigest()
def baseline():
    m=load((BASE/'manifest.json').read_bytes())
    require(m['repository']=='SAGE-X-project/sage-spec' and m['revision']==REVISION and m['status']=='PROPOSAL_NOT_ADOPTED','proposal provenance')
    require(set(m['files'])==FILES,'snapshot membership')
    for name,digest in m['files'].items():require(sha((BASE/name).read_bytes())==digest,'snapshot hash')
    cases=load((BASE/'cases.json').read_bytes());require(len(cases['cases'])==40 and all(c['status']=='NOT_RUN' for c in cases['cases']),'case promotion')
    return m

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve()
    try:
        require(out!=ROOT and not out.is_relative_to(ROOT/'docs/evidence') and not out.exists(),'preserve existing evidence')
        m=baseline();out.mkdir(parents=True,exist_ok=False)
    except (ValueError,OSError,KeyError) as error:p.exit(2,str(error)+'\n')
    r=dict(kind='mcp-setup-abstract-model',status='RUNNING',actual_core_execution=False,external_review=False,protocol_execution='NOT_RUN',adoption='PROPOSAL_NOT_ADOPTED',conformance='NOT_ESTABLISHED',lifecycle={'NOT_RUN':37},proposal_cases={'NOT_RUN':40},baseline=m,model_sha256=sha((ROOT/'scripts/mcp_setup_model.py').read_bytes()),inspector_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),explorations=[],abstraction=dict(clock_ms=[0,29999,30000,30001],request_capacities=[2,3],cryptography='ASSUMED_AUTHENTICATED_INPUTS',io='SYMBOLIC_SEND_COMPLETION',roles='SEPARATE_LOCAL_OWNERS',claim='Finite reachability and safety invariants only; not complete protocol verification.'))
    try:
        for role in ('client','server'):
            for limit in (2,3):r['explorations'].append(explore(role,limit))
        r['status']='MODEL_CHECKED'
    except Exception as error:r.update(status='FAIL',counterexample=str(error))
    (out/'report.json').write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(dict(status=r['status'],states=sum(x['states'] for x in r['explorations']),transitions=sum(x['transitions'] for x in r['explorations']),actual_core_execution=False)))
    return 0 if r['status']=='MODEL_CHECKED' else 1
if __name__=='__main__':raise SystemExit(main())
