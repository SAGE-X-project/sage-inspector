"""IPC regression checks; these are not HTTP conformance expectations."""
import json,subprocess,sys
for executable in sys.argv[1:]:
    base=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',case_id='http-probe',operation='rfc9421.base',input=dict(request_hex='',response_hex='',public_key_hex='',body_repeat=1))
    for invalid in [dict(request_hex='zz'),dict(body_repeat=0),dict(body_repeat=(16<<20)+2)]:
        q=dict(base,input=dict(base['input'],**invalid))
        p=subprocess.run([executable],input=json.dumps(q),text=True,capture_output=True,timeout=5)
        assert p.returncode!=0 and not p.stdout,(executable,invalid,p.stdout)
    q=dict(base,operation='sage.http.verify')
    p=subprocess.run([executable],input=json.dumps(q),text=True,capture_output=True,timeout=5)
    assert p.returncode==0 and json.loads(p.stdout)['verdict']=='UNSUPPORTED'
    q=dict(base,input=dict(base['input'],request_hex=b'POST https://agent.example/ HTTP/1.1\r\nHost: agent.example\r\nContent-Length: 0\r\n\r\n'.hex()))
    p=subprocess.run([executable],input=json.dumps(q),text=True,capture_output=True,timeout=5)
    assert p.returncode==0 and json.loads(p.stdout)['verdict']=='REJECT'
    print(executable+': 5 HTTP adapter contract checks passed')
if len(sys.argv)==1:raise SystemExit('Provide adapter executables')
