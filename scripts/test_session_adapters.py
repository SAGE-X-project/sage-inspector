"""Run against operator-supplied real core adapter executables; malformed controls must not become REJECT."""
import copy,json,subprocess,sys
from pathlib import Path
suite=json.loads((Path(__file__).resolve().parents[1]/'vectors/0.10.0/session-records.json').read_text())
for executable in sys.argv[1:]:
    for op in ('sage.session.record.open','sage.session.record.seal'):
        c=next(c for c in suite['cases'] if c['operation']==op)
        request=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',case_id='malformed-control',operation=op,input=c['input'])
        mutations=[('seed_hex',None),('th_hex','zz'),('sid',None),('direction','wrong'),('caller_aad_hex',None)]
        if op.endswith('seal'): mutations += [('plaintext',None),('plaintext',{'byte':97,'length':8388574})]
        for field,value in mutations:
            q=copy.deepcopy(request);q['input'][field]=value
            p=subprocess.run([executable],input=json.dumps(q),text=True,capture_output=True,timeout=10)
            assert p.returncode!=0 and not p.stdout,(executable,field,p.stdout)
    print(executable+': malformed controls remain adapter errors')
