"""Pin the adopted A2A/DID inventory without copying historical verdicts."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
from current_spec_catalog import ROOT, catalog, index, load, require, sha

BASE = 'verification/0.10.0/a2a-did'
SPEC_REVISION = '06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b'
FROZEN_REVISION = '1820ab5eafb843e1c13f4c46c34aeeb28d934ac9'
MANIFEST_SHA256 = '149838928de7c09f58d9c519f483d5a2014c6d889ea2ed083e28ea0f4419307a'


def verify(root=ROOT, spec_root=None):
    require(sha((root/BASE/'manifest.json').read_bytes()) == MANIFEST_SHA256,
            'adopted manifest drift')
    manifest, trace, mapped = catalog(root, spec_root, BASE)
    require(manifest['spec_revision']==SPEC_REVISION and len(trace['cases'])==583
            and len(trace['rules'])==104 and len(trace['requirements'])==45
            and len(trace['mandatory_subscenarios'])==26, 'adopted identity')
    frozen = load((root/'verification/0.10.0/design-baseline/traceability.json').read_bytes())
    old = index(frozen['cases'], 'frozen case'); new = index(trace['cases'], 'adopted case')
    require(len(old)==489 and set(old)<=set(new)
            and all(new[k]==v for k,v in old.items()), 'frozen case preservation')
    added = [v for k,v in new.items() if k not in old]
    require(dict(Counter(x['rule_id'].split('-')[0] for x in added))==
            {'A2AB':64, 'DIDP':28, 'TABLE':2}
            and all(x['rule_id']=='TABLE-08' for x in added if x['rule_id'].startswith('TABLE-')),
            'adopted case delta')
    return manifest, trace, mapped


def inventory(root=ROOT, spec_root=None):
    manifest,trace,mapped=verify(root,spec_root)
    rules=index(trace['rules'],'rule')
    return {'schema_version':1, 'kind':'a2a-did-adopted-inventory',
            'protocol_version':'0.10.0', 'spec_revision':SPEC_REVISION,
            'historical_evidence_revision':FROZEN_REVISION,
            'status':'INVENTORY_ONLY', 'conformance':'NOT_ESTABLISHED',
            'counts':{'requirements':45,'rules':104,'cases':583,
                      'mandatory_subscenarios':26,'added':{'A2AB':64,'DIDP':28,'TABLE':2}},
            'cases':[{'id':x['id'],'rule_id':x['rule_id'],
                      'source':rules[x['rule_id']]['source'],
                      'verification_tracks':mapped[x['id']]['verification_tracks'],
                      'status':'NOT_RUN'} for x in trace['cases']]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        report=inventory(spec_root=args.spec_root)
        if args.output is not None:
            args.output.write_text(json.dumps(report,indent=2)+'\n')
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:
        parser.exit(1,'A2A/DID inventory FAIL: '+str(e)+'\n')
    print('Adopted A2A/DID inventory: 583 cases; 94 additions; no conformance evidence')

if __name__=='__main__':main()
