"""Recheck saved native MCP restart evidence without executing a core or network peer."""
import argparse
import itertools
import json
from mcp_evidence_json import loads as strict_json, equal as typed_equal
from pathlib import Path
import sys
from run_mcp_core_runtime import digest, observed
from run_mcp_setup_interop import TESTS, validate as setup
from mcp_protected_support import validate, validate_recovery

PAIRS = tuple(a+'-to-'+b for a,b in itertools.product(('go','rust'),repeat=2))


def audit(root):
    if not __debug__:
        raise ValueError('signature verification requires Python assertions')
    root = Path(root).resolve(strict=True)
    report = strict_json((root/'report.json').read_bytes())
    if (report.get('kind') != 'mcp-native-protected-interop' or report.get('status') != 'PASS'
            or report.get('completed_recovery') != 'SELECTED_ASSERTIONS_PASS'):
        raise ValueError('complete restart report required')
    baseline, recovery = report['pairs'], report['restart']
    if [p['pair'] for p in baseline] != list(PAIRS) or any('recovery' in p for p in baseline):
        raise ValueError('baseline pair inventory')
    if [(p.get('recovery'),p['pair']) for p in recovery] != [(m,p) for m in ('server','client') for p in PAIRS]:
        raise ValueError('recovery pair inventory')
    checks = []
    for row in baseline + recovery:
        mode = row.get('recovery')
        directory = root/('reopen-'+mode)/row['pair'] if mode else root/row['pair']
        required = {'frames.json','intent.json','client.json','server.json','client.journal',
                    'server.journal','client.log','server.log'}
        if mode: required.add('server.journal.before')
        if mode == 'client': required.add('client.journal.before')
        files = row['files']
        if not required.issubset(files): raise ValueError('missing evidence hash')
        for name, expected in files.items():
            if not name or Path(name).name != name: raise ValueError('unsafe evidence name')
            path = directory/name
            if not path.resolve().is_relative_to(root): raise ValueError('evidence outside root')
            if digest(path) != expected: raise ValueError('evidence hash mismatch: '+name)
        left,right = row['pair'].split('-to-')
        if row.get('status') != 'PASS' or not typed_equal(row.get('exit_codes'), [0,0]):
            raise ValueError('bridge execution failed')
        for language,role in ((right,'server'),(left,'client')):
            if not observed(language,TESTS[language],(directory/(role+'.log')).read_text(),0):
                raise ValueError('exact bridge execution missing')
        frames = strict_json((directory/'frames.json').read_bytes())
        requests = [bytes.fromhex(raw) for raw in frames['requests']]
        responses = [bytes.fromhex(raw) for raw in frames['responses']]
        checked = setup(requests[:4],responses[:4])
        if mode:
            original = root/row['pair']
            for name in ('server.journal','client.journal') if mode == 'client' else ('server.journal',):
                if (directory/(name+'.before')).read_bytes() != (original/name).read_bytes():
                    raise ValueError('recovery journal differs from baseline')
            if (directory/'intent.json').read_bytes() != (original/'intent.json').read_bytes():
                raise ValueError('recovery intent differs from baseline')
            checked.update(validate_recovery(directory,requests,responses,checked,mode))
        else:
            checked.update(validate(directory,requests,responses,checked))
        if any(not typed_equal(row.get(key), value) for key,value in checked.items()):
            raise ValueError('reported observation differs from recomputed evidence')
        checks.append(dict(pair=row['pair'],mode=mode or 'baseline',status='PASS'))
    return dict(kind='mcp-saved-evidence-audit',status='PASS',checks=checks,
                conformance='NOT_ESTABLISHED',report_sha256=digest(root/'report.json'),
                scope='Saved frames, journals and execution logs; no artifact provenance authentication')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,required=True)
    a=p.parse_args()
    try:
        result=audit(a.evidence)
    except Exception as e:
        result=dict(kind='mcp-saved-evidence-audit',status='FAIL',error=str(e))
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='PASS' else 1


if __name__=='__main__': sys.exit(main())
