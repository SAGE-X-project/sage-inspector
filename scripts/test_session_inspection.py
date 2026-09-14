"""Mutation tests for session fixtures, report verification and execution failures."""
import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from inspect_session import ROOT,validate_report,validate_scenario
class SessionInspectionTests(unittest.TestCase):
    def test_independent_audit_detects_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);source=ROOT/'vectors/0.10.0'
            for f in ('session-records.json','session-manifest.json'): shutil.copyfile(source/f,d/f)
            shutil.copytree(source/'session-scenarios',d/'session-scenarios')
            def audit(): return subprocess.run(['node',str(ROOT/'scripts/check_session_vectors.js'),str(d)],capture_output=True,timeout=15).returncode
            self.assertEqual(audit(),0)
            raw=(d/'session-records.json').read_bytes();suite=json.loads(raw)
            for mutate in ('key','cipher','rejection'):
                changed=copy.deepcopy(suite)
                if mutate=='key': changed['cases'][0]['expected']['output']['key_hex']='00'*32
                if mutate=='cipher': changed['cases'][1]['input']['record_hex']='00'*36
                if mutate=='rejection': next(c for c in changed['cases'] if c['id']=='aad-seal-4034')['expected']['verdict']='ACCEPT'
                (d/'session-records.json').write_text(json.dumps(changed));self.assertNotEqual(audit(),0)
            (d/'session-records.json').write_bytes(raw)
            f=d/'session-scenarios/session-concurrent-duplicate.json';s=json.loads(f.read_text());s['steps'][1]['effects']['accepted']=16;f.write_text(json.dumps(s));self.assertNotEqual(audit(),0)
    def test_primitive_reports(self):
        raw=(ROOT/'vectors/0.10.0/session-records.json').read_bytes()
        report=json.loads((ROOT/'docs/evidence/session/go/session-records.json').read_text())
        validate_report(raw,report)
        for kind in ('missing','hash','promote'):
            changed=copy.deepcopy(report)
            if kind=='missing': changed['results'].pop()
            if kind=='hash': changed['suite_sha256']='0'*64
            if kind=='promote': next(x for x in changed['results'] if x['status']=='UNSUPPORTED')['status']='PASS'
            with self.assertRaises(ValueError): validate_report(raw,changed)
    def test_scenario_reports_require_observed_effects(self):
        raw=(ROOT/'vectors/0.10.0/session-scenarios/session-concurrent-duplicate.json').read_bytes();f=json.loads(raw)
        report=dict(schema_version=2,protocol_version='0.10.0',profile='stateful-scenario',fixture_sha256=hashlib.sha256(raw).hexdigest(),case_id=f['id'],status='PASS',steps=[])
        for s in f['steps']:
            report['steps'].append(dict(step_id=s['id'],input=s['input'],expected=s['expected'],expected_effects=s['effects'],status='PASS',actual=dict(schema_version=2,case_id=f['id'],step_id=s['id'],**s['expected'],effects=s['effects'])))
        validate_scenario(raw,report)
        for kind in ('missing','effects','identity','unsupported','input'):
            changed=copy.deepcopy(report)
            if kind=='missing': changed['steps'].pop()
            if kind=='effects': changed['steps'][1]['actual']['effects']={'accepted':16}
            if kind=='identity': changed['steps'][1]['actual']['step_id']='wrong'
            if kind=='unsupported': changed['steps'][0]['status']='UNSUPPORTED';changed['steps'][0]['actual']['verdict']='UNSUPPORTED'
            if kind=='input': changed['steps'][1]['input']={}
            with self.assertRaises(ValueError): validate_scenario(raw,changed)
    def test_runner_error_not_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=subprocess.run([sys.executable,str(ROOT/'scripts/inspect_session.py'),'--runner',sys.executable,'--adapter',sys.executable,'--subject','test','--revision','test','--output-dir',tmp+'/out'],capture_output=True,timeout=10)
            self.assertEqual(p.returncode,2)
            self.assertEqual(json.loads(Path(tmp+'/out/summary.json').read_text())['status'],'ERROR')
if __name__=='__main__': unittest.main()
