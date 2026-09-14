"""Exercise actual CLI error paths with an inert scripted peer, never a host."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from inspect_guard import validate_scenario
from test_guard_gate_inspection import NAMES,fixture,rejection_index

RUNNER=Path(sys.argv.pop(1)).resolve() if len(sys.argv)>1 else None
PEER='''import json,sys,time
from pathlib import Path
root=Path(__file__).parent
data=json.loads((root/'responses.json').read_text())
for i,line in enumerate(sys.stdin):
    q=json.loads(line)
    if set(q)!={'schema_version','protocol_version','profile','case_id','step_id','operation','input'}:sys.exit(91)
    with (root/'trace.jsonl').open('a') as trace:trace.write(json.dumps(q)+'\\n')
    if i==data['fault'] and data['mode']=='exit':sys.exit(7)
    if i==data['fault'] and data['mode']=='timeout':time.sleep(2)
    print(json.dumps(data['responses'][i]),flush=True)
'''


class GuardRuntimeTests(unittest.TestCase):
    def run_path(self,name,mode):
        self.assertIsNotNone(RUNNER,'pass the built sage-scenario executable')
        f=fixture(name);i=rejection_index(f)
        # This timeout tests the Inspector adapter deadline, not a real host hook.
        if mode=='timeout':f['steps'][i]['timeout_ms']=200
        raw=json.dumps(f).encode()
        responses=[dict(schema_version=2,case_id=f['id'],step_id=s['id'],**copy.deepcopy(s['expected']),effects=copy.deepcopy(s['effects'])) for s in f['steps']]
        if mode=='accept':responses[i]['verdict']='ACCEPT'
        if mode=='effect':responses[i]['effects']['dispatch']+=1
        if mode=='missing':responses[i].pop('effects')
        if mode=='unsupported':responses[i].update(verdict='UNSUPPORTED',output={},effects={})
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);file=root/'scenario.json';file.write_bytes(raw)
            peer=root/'peer.py';peer.write_text('#!'+sys.executable+'\n'+PEER);peer.chmod(0o700)
            (root/'responses.json').write_text(json.dumps(dict(responses=responses,mode=mode,fault=i)))
            start=time.monotonic()
            p=subprocess.run([str(RUNNER),'-scenario',str(file),'-adapter',str(peer),'-subject','scripted-guard-peer','-revision','test-only'],capture_output=True,text=True,timeout=20)
            elapsed=time.monotonic()-start
            code=0 if mode=='ok' else 3 if mode=='unsupported' else 1
            self.assertEqual(p.returncode,code,p.stderr)
            r=json.loads(p.stdout);validate_scenario(raw,r)
            self.assertEqual(r['status'],{0:'PASS',1:'FAIL',3:'INCOMPLETE'}[code])
            self.assertEqual(r['subject']['executable_sha256'],hashlib.sha256(peer.read_bytes()).hexdigest())
            trace=[json.loads(line) for line in (root/'trace.jsonl').read_text().splitlines()]
            self.assertEqual(len(trace),len(f['steps']) if mode=='ok' else i+1)
            for q,s in zip(trace,f['steps']):
                self.assertEqual(q['input'],s['input']);self.assertEqual(q['operation'],s['operation']);self.assertEqual(q['step_id'],s['id']);self.assertEqual(q['case_id'],f['id'])
            if mode!='ok':
                self.assertEqual(r['steps'][i]['status'],'UNSUPPORTED' if mode=='unsupported' else 'FAIL')
                for s in r['steps'][i+1:]:self.assertEqual(s['status'],'NOT_RUN');self.assertNotIn('actual',s)
            if mode in ('exit','timeout','missing'):
                self.assertTrue(r['steps'][i]['reason']);self.assertNotIn('actual',r['steps'][i])
            if mode=='timeout':
                self.assertEqual(r['steps'][i]['reason'],'step timeout')
                self.assertLess(elapsed,5)

    def test_scripted_gate_paths(self):
        for name in NAMES:
            for mode in ('ok','accept','effect','missing','unsupported','exit'):
                with self.subTest(name=name,mode=mode):self.run_path(name,mode)

    def test_adapter_timeout_is_failure_not_rejection(self):
        self.run_path('guard-gate-timeout','timeout')

if __name__=='__main__':unittest.main()
