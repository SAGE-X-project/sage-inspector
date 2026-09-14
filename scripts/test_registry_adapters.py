"""Explicit real adapter error-path checks; inputs never carry expectations."""
import copy,json,subprocess,sys
from pathlib import Path
suite=json.loads((Path(__file__).resolve().parents[1]/'vectors/0.10.0/registry-records.json').read_text())
for adapter in sys.argv[1:]:
    for op in ('sage.did.validate','sage.registry.pop.verify'):
        case=next(c for c in suite['cases'] if c['operation']==op)
        request=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',case_id='invalid-control',operation=op,input=case['input'])
        mutations=[('did',None)]
        if op.endswith('pop.verify'):mutations += [('name',None),('alg',None),('public_key_hex','invalid'),('signature_hex',None)]
        for key,value in mutations:
            q=copy.deepcopy(request);q['input'][key]=value
            p=subprocess.run([adapter],input=json.dumps(q),capture_output=True,text=True,timeout=10)
            assert p.returncode!=0 and not p.stdout,(adapter,key,p.stdout)
    print(adapter+': invalid IPC remains an execution error')
