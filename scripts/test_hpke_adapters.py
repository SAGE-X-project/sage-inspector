"""HPKE adapter IPC errors must not count as valid protocol rejections."""
import json
import subprocess
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
suite=json.loads((root/'vectors/0.10.0/hpke-primitives.json').read_text())
base={'schema_version':1,'protocol_version':'0.10.0','profile':'primitive-foundation','case_id':'ipc-probe','operation':'rfc9180.export','input':suite['cases'][0]['input']}
for executable in sys.argv[1:]:
    for mutation in [{'enc_hex':'zz'},{'private_key_hex':'00'}, {'info_hex':None}]:
        request=dict(base,input=dict(base['input'],**mutation))
        result=subprocess.run([executable],input=json.dumps(request),capture_output=True,text=True,timeout=5)
        assert result.returncode!=0 and not result.stdout,(executable,mutation,result.stdout)
    request=dict(base,operation='sage.hpke.derive',input={})
    result=subprocess.run([executable],input=json.dumps(request),capture_output=True,text=True,timeout=5)
    assert result.returncode==0 and json.loads(result.stdout)['verdict']=='UNSUPPORTED'
    print(executable+': 4 HPKE adapter contract checks passed')
if len(sys.argv)==1:
    raise SystemExit('Provide adapter executables')
