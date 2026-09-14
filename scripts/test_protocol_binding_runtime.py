"""Actual Inspector CLIs with scripted local observations; no network or core."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from inspect_hpke import validate_report
from inspect_session import validate_scenario
from protocol_test_support import selected_suite, websocket_suite
from test_protocol_binding_inspection import hpke_scenario

CONFORMANCE=Path(sys.argv.pop(1)).resolve() if len(sys.argv)>1 else None
SCENARIO=Path(sys.argv.pop(1)).resolve() if len(sys.argv)>1 else None
PEER='''import json,sys
from pathlib import Path
root=Path(__file__).parent
responses=json.loads((root/'responses.json').read_text())
for line in sys.stdin:
    q=json.loads(line)
    fields={'schema_version','protocol_version','profile','case_id','operation','input'}
    if q['schema_version']==2: fields.add('step_id')
    if set(q)!=fields: sys.exit(91)
    with (root/'trace.jsonl').open('a') as trace: trace.write(json.dumps(q)+'\\n')
    key=q['step_id'] if q['schema_version']==2 else q['case_id']
    print(json.dumps(responses[key]),flush=True)
'''


def peer_files(root, responses):
    peer=root/'peer.py';peer.write_text('#!'+sys.executable+'\n'+PEER);peer.chmod(0o700)
    (root/'responses.json').write_text(json.dumps(responses))
    return peer


def trace_check(test,root,report,peer,items):
    test.assertEqual(report['subject']['executable_sha256'],hashlib.sha256(peer.read_bytes()).hexdigest())
    trace=[json.loads(line) for line in (root/'trace.jsonl').read_text().splitlines()]
    test.assertEqual(len(trace),len(items))
    for q,item in zip(trace,items):
        test.assertEqual(q['input'],item['input']);test.assertEqual(q['operation'],item['operation'])
        test.assertEqual(q.get('step_id',q['case_id']),item['id'])


class ProtocolRuntimeTests(unittest.TestCase):
    def test_primitive_link_judgments(self):
        self.assertIsNotNone(CONFORMANCE,'pass sage-conformance and sage-scenario executables')
        suites=[selected_suite(n) for n in ('hpke-schedule','session-records','http-signatures','http-boundaries')]+[websocket_suite()]
        for suite in suites:
            for mode in ('ok','accept','identity','unsupported'):
                with self.subTest(suite=suite['id'],mode=mode),tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);raw=json.dumps(suite).encode();file=root/'suite.json';file.write_bytes(raw)
                    responses={c['id']:dict(schema_version=1,case_id=c['id'],**copy.deepcopy(c['expected'])) for c in suite['cases']}
                    ident=next(c['id'] for c in suite['cases'] if c['expected']['verdict']=='REJECT')
                    if mode=='accept':responses[ident]['verdict']='ACCEPT'
                    if mode=='identity':responses[ident]['case_id']='unrelated'
                    if mode=='unsupported':responses[ident].update(verdict='UNSUPPORTED',output={})
                    peer=peer_files(root,responses)
                    p=subprocess.run([str(CONFORMANCE),'-suite',str(file),'-adapter',str(peer),'-subject','scripted-protocol-peer','-revision','test-only'],capture_output=True,text=True,timeout=20)
                    code=0 if mode=='ok' else 3 if mode=='unsupported' else 1
                    self.assertEqual(p.returncode,code,p.stderr)
                    report=json.loads(p.stdout);validate_report(raw,report)
                    self.assertEqual(report['status'],{0:'PASS',1:'FAIL',3:'INCOMPLETE'}[code])
                    row=next(r for r in report['results'] if r['case_id']==ident)
                    self.assertEqual(row['status'],'PASS' if mode=='ok' else 'UNSUPPORTED' if code==3 else 'FAIL')
                    trace_check(self,root,report,peer,suite['cases'])

    def test_hpke_state_confirmation(self):
        self.assertIsNotNone(SCENARIO,'pass sage-conformance and sage-scenario executables')
        for name in ('valid','wrong-ack','wrong-pending'):
            for mode in ('ok','extra-session'):
                with self.subTest(name=name,mode=mode),tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);f=hpke_scenario(name);raw=json.dumps(f).encode();file=root/'scenario.json';file.write_bytes(raw)
                    responses={s['id']:dict(schema_version=2,case_id=f['id'],step_id=s['id'],**copy.deepcopy(s['expected']),effects=copy.deepcopy(s['effects'])) for s in f['steps']}
                    if mode=='extra-session':responses[f['steps'][1]['id']]['effects']['sessions_created']+=1
                    peer=peer_files(root,responses)
                    p=subprocess.run([str(SCENARIO),'-scenario',str(file),'-adapter',str(peer),'-subject','scripted-hpke-peer','-revision','test-only'],capture_output=True,text=True,timeout=20)
                    self.assertEqual(p.returncode,0 if mode=='ok' else 1,p.stderr)
                    report=json.loads(p.stdout);validate_scenario(raw,report)
                    self.assertEqual(report['status'],'PASS' if mode=='ok' else 'FAIL')
                    trace_check(self,root,report,peer,f['steps'] if mode=='ok' else f['steps'][:2])
                    if mode!='ok':
                        for step in report['steps'][2:]:self.assertEqual(step['status'],'NOT_RUN');self.assertNotIn('actual',step)

if __name__=='__main__':unittest.main()
