"""Transport/error regression checks against supplied real adapter executables."""
import json, subprocess, sys

def request(op, data):
    return dict(schema_version=1, protocol_version='0.10.0', profile='primitive-foundation', case_id='probe', operation=op, input=data)

for exe in sys.argv[1:]:
    def call(q):
        return subprocess.run([exe], input=json.dumps(q), text=True, capture_output=True, timeout=5)
    q=request('unknown.operation', {})
    p=call(q); assert p.returncode==0 and json.loads(p.stdout)['verdict']=='UNSUPPORTED'
    for bad in [dict(q, protocol_version='bad'), dict(q, expected={'verdict':'ACCEPT'})]:
        p=call(bad); assert p.returncode!=0 and not p.stdout
    p=call(request('json.syntax',{'document_hex':'ff00zz'})); assert p.returncode!=0 and not p.stdout
    p=call(request('json.syntax',{'document_hex':'7b7d'})); o=json.loads(p.stdout)
    assert p.returncode==0 and o==dict(schema_version=1,case_id='probe',verdict='ACCEPT',output={'valid':True})
    p=call(request('json.syntax',{'document_hex':'7b'})); assert p.returncode==0 and json.loads(p.stdout)['verdict']=='REJECT'
    print(exe+': 6 transport/error checks passed')
if len(sys.argv)<2: raise SystemExit('Provide at least one adapter executable')
