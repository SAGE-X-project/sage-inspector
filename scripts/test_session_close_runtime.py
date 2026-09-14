"""Actual CLI with ordered scripted observations, never live race reproduction."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from inspect_session import validate_scenario
from test_session_close_inspection import close_fixture

RUNNER=Path(sys.argv.pop(1)).resolve() if len(sys.argv)>1 else None
PEER='''import json,sys
from pathlib import Path
root=Path(__file__).parent
responses=json.loads((root/'responses.json').read_text())
for i,line in enumerate(sys.stdin):
    request=json.loads(line)
    if set(request)!={'schema_version','protocol_version','profile','case_id','step_id','operation','input'}: sys.exit(91)
    with (root/'requests.jsonl').open('a') as trace: trace.write(json.dumps(request)+'\\n')
    if i>=len(responses): sys.exit(92)
    print(json.dumps(responses[i]),flush=True)
'''


class CloseRuntimeTests(unittest.TestCase):
    def test_ordered_cli_judgments(self):
        self.assertIsNotNone(RUNNER,'pass the built sage-scenario executable')
        for order in ('close-first','receive-first','replay-after-close'):
            f=close_fixture(order); raw=json.dumps(f).encode(); n=len(f['steps'])
            for mode in ('ok','late-accept','dispatch','late-id','keys','unsupported-close'):
                with self.subTest(order=order,mode=mode),tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);fixture=root/'scenario.json';fixture.write_bytes(raw)
                    responses=[dict(schema_version=2,case_id=f['id'],step_id=s['id'],**copy.deepcopy(s['expected']),effects=copy.deepcopy(s['effects'])) for s in f['steps']]
                    failure=n-2
                    if mode=='late-accept': responses[failure]['verdict']='ACCEPT'
                    if mode=='dispatch': responses[failure]['effects']['dispatch']+=1
                    if mode=='late-id': responses[failure]['step_id']=f['steps'][0]['id']
                    if mode=='keys': failure=n-1;responses[failure]['output']['keys_available']=True
                    if mode=='unsupported-close':
                        failure=1 if order=='close-first' else 2
                        responses[failure].update(verdict='UNSUPPORTED',output={},effects={})
                    (root/'responses.json').write_text(json.dumps(responses))
                    peer=root/'peer.py';peer.write_text('#!'+sys.executable+'\n'+PEER);peer.chmod(0o700)
                    result=subprocess.run([str(RUNNER),'-scenario',str(fixture),'-adapter',str(peer),'-subject','scripted-close-peer','-revision','test-only'],capture_output=True,text=True,timeout=20)
                    code=0 if mode=='ok' else 3 if mode=='unsupported-close' else 1
                    self.assertEqual(result.returncode,code,result.stderr)
                    report=json.loads(result.stdout);validate_scenario(raw,report)
                    self.assertEqual(report['status'],{0:'PASS',1:'FAIL',3:'INCOMPLETE'}[code])
                    self.assertEqual(report['subject']['executable_sha256'],hashlib.sha256(peer.read_bytes()).hexdigest())
                    trace=[json.loads(line) for line in (root/'requests.jsonl').read_text().splitlines()]
                    self.assertEqual(len(trace),n if mode=='ok' else failure+1)
                    for request,step in zip(trace,f['steps']):
                        self.assertEqual(request['step_id'],step['id']);self.assertEqual(request['input'],step['input'])
                        self.assertEqual(request['operation'],step['operation']);self.assertEqual(request['case_id'],f['id'])
                    if mode!='ok':
                        self.assertEqual(report['steps'][failure]['status'],'UNSUPPORTED' if code==3 else 'FAIL')
                        for step in report['steps'][failure+1:]:
                            self.assertEqual(step['status'],'NOT_RUN');self.assertNotIn('actual',step)

if __name__=='__main__': unittest.main()
