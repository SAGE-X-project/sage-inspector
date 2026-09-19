"""Offline integrity checks and bounded CLI execution, not MCP handshake tests."""
import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
import inspect_mcp_setup as checker
from inspect_mcp_setup import ROOT,CONTRACT,audit,load,validate

class Review(unittest.TestCase):
    def setUp(self):self.c=load((ROOT/CONTRACT).read_bytes())
    def reject(self,change):
        c=copy.deepcopy(self.c);change(c)
        with self.assertRaises((ValueError,TypeError)):validate(c)
    def test_scope(self):
        r=audit();self.assertEqual(r['authenticated_setup'],'NOT_IMPLEMENTED');self.assertFalse(r['actual_core_execution'])
        self.assertEqual(r['lifecycle'],dict(status='NOT_RUN',scenarios=37));self.assertEqual(r['conformance'],'NOT_ESTABLISHED')
        self.assertEqual(set(r['support_source_identity'].values()),{'NOT_CHECKED'})
    def test_no_promotion(self):
        self.reject(lambda c:c.update(status='PASS'))
        self.reject(lambda c:c['decisions'][0].update(status='COMPLETE'))
        self.reject(lambda c:c.update(actual_core_execution=True))
    def test_required_decisions(self):
        self.reject(lambda c:c['decisions'].pop())
        self.reject(lambda c:c['decisions'].reverse())
        self.reject(lambda c:c['decisions'].__setitem__(1,c['decisions'][0]))
    def test_version_and_references(self):
        self.reject(lambda c:c.update(mcp_baseline='latest'))
        self.reject(lambda c:c['references'].update(lifecycle='https://example.com'))
    def test_source_binding(self):
        self.reject(lambda c:c.update(integration_sha256='0'*64))
        self.reject(lambda c:c['support_sources']['go'].update(path='../outside'))
        self.reject(lambda c:c['support_sources']['rust'].update(sha256='main'))
    def test_rationale_and_evidence(self):
        self.reject(lambda c:c['decisions'][0].update(proposal=''))
        self.reject(lambda c:c['decisions'][0].update(required_evidence=[]))
        self.reject(lambda c:c['decisions'][0]['required_evidence'].append(c['decisions'][0]['required_evidence'][0]))
    def test_changed_support_source(self):
        original=checker.read
        def changed(root,path):return b'changed' if path==checker.SUPPORT['go'] else original(root,path)
        with mock.patch.object(checker,'integration_audit',return_value=checker.integration_audit()),mock.patch.object(checker,'read',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'support source mismatch'):audit(core_roots={'go':ROOT})
    def test_duplicate_json(self):
        with self.assertRaises(ValueError):load(b'{"status":"OPEN","status":"PASS"}')

class CLI(unittest.TestCase):
    def run_cli(self,*args):
        return subprocess.run([sys.executable,str(ROOT/'scripts/inspect_mcp_setup.py'),*map(str,args)],capture_output=True,text=True,timeout=20,cwd=ROOT)
    def test_real_report_and_existing_output(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'review';run=self.run_cli('--output',out);self.assertEqual(run.returncode,3,run.stderr)
            raw=(out/'report.json').read_bytes();r=json.loads(raw)
            self.assertEqual(r['review_audit'],'PASS');self.assertEqual(r['status'],'SPEC_DECISION_REQUIRED')
            self.assertEqual((out/'contract.json').read_bytes(),(ROOT/CONTRACT).read_bytes())
            self.assertEqual(self.run_cli('--output',out).returncode,2);self.assertEqual((out/'report.json').read_bytes(),raw)
    def test_missing_core_and_protected_output(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'missing';self.assertEqual(self.run_cli('--output',out,'--go-root',Path(d)/'absent').returncode,2);self.assertFalse(out.exists())
        self.assertEqual(self.run_cli('--output',ROOT/'docs/evidence/forbidden-setup').returncode,2)
        self.assertEqual(self.run_cli('--output',ROOT).returncode,2)

if __name__=='__main__':unittest.main()
