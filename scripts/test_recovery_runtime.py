"""Run the actual CLI against a scripted local peer; no core or host execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from inspect_session import ROOT, validate_scenario

# Explicit executable argument prevents silently skipping runtime coverage in CI.
RUNNER = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else None
PEER = '''import json,sys
from pathlib import Path
root=Path(__file__).parent
data=json.loads((root/'responses.json').read_text())
for index,line in enumerate(sys.stdin):
    request=json.loads(line)
    if set(request)!={'schema_version','protocol_version','profile','case_id','step_id','operation','input'}:
        sys.exit(91)
    with (root/'requests.jsonl').open('a') as trace:
        trace.write(json.dumps(request)+'\\n')
    if index>=len(data['responses']): sys.exit(92)
    if index==3 and data['mode'] in ('exit','eof'):
        sys.exit(7 if data['mode']=='exit' else 0)
    response=data['responses'][index]
    response.update(schema_version=2,case_id=request['case_id'],step_id=request['step_id'])
    if index==3 and data['mode']=='unsupported':
        response.update(verdict='UNSUPPORTED',output={},effects={})
    if index==3 and data['mode']=='effects': response['effects']['closed']=0
    print(json.dumps(response),flush=True)
sys.exit(7 if data['mode']=='exit-after-last' else 0)
'''


class RecoveryRuntimeTests(unittest.TestCase):
    def test_cli_process_contract(self):
        self.assertIsNotNone(RUNNER, 'pass the built sage-scenario executable')
        fixture = ROOT/'vectors/0.10.0/session-scenarios/session-restart.json'
        raw = fixture.read_bytes(); f = json.loads(raw)
        # The peer is explicitly scripted, not a state machine or core adapter.
        responses = [dict(**s['expected'], effects=s['effects']) for s in f['steps']]
        for mode, code, status, requests in [
            ('ok',0,'PASS',9), ('exit',1,'FAIL',4), ('eof',1,'FAIL',4),
            ('effects',1,'FAIL',4), ('unsupported',3,'INCOMPLETE',4),
            ('exit-after-last',1,'FAIL',9),
        ]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); peer=root/'peer.py'
                peer.write_text('#!'+sys.executable+'\n'+PEER); peer.chmod(0o700)
                (root/'responses.json').write_text(json.dumps(dict(mode=mode,responses=responses)))
                p=subprocess.run([str(RUNNER),'-scenario',str(fixture),'-adapter',str(peer),
                                  '-subject','scripted-recovery-peer','-revision','test-only'],capture_output=True,text=True,timeout=20)
                self.assertEqual(p.returncode,code,p.stderr)
                report=json.loads(p.stdout); self.assertEqual(report['status'],status)
                self.assertEqual(report['subject']['name'],'scripted-recovery-peer')
                self.assertEqual(report['subject']['executable_sha256'],hashlib.sha256(peer.read_bytes()).hexdigest())
                validate_scenario(raw,report)
                trace=[json.loads(line) for line in (root/'requests.jsonl').read_text().splitlines()]
                self.assertEqual(len(trace),requests)
                for actual, step in zip(trace,f['steps']):
                    self.assertEqual(actual['input'],step['input'])
                    self.assertEqual(actual['operation'],step['operation'])
                    self.assertEqual(actual['step_id'],step['id'])
                    self.assertEqual(actual['case_id'],f['id'])
                if requests==4:
                    self.assertEqual(report['steps'][3]['status'],'UNSUPPORTED' if mode=='unsupported' else 'FAIL')
                    for step in report['steps'][4:]:
                        self.assertEqual(step['status'],'NOT_RUN'); self.assertNotIn('actual',step)
                if mode=='exit-after-last':
                    self.assertTrue(report['reason'])
                    self.assertTrue(all(s['status']=='PASS' for s in report['steps']))

if __name__=='__main__': unittest.main()
