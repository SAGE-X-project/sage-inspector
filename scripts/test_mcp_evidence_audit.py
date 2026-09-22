"""Offline checker controls using public captured frames and synthetic process logs."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from audit_mcp_evidence import PAIRS, TESTS, audit
from run_mcp_core_runtime import digest
from run_mcp_setup_interop import validate as setup
from mcp_protected_support import validate, validate_recovery

HERE=Path(__file__).resolve().parent


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.template.cleanup)
        root=Path(cls.template.name)
        report=dict(kind='mcp-native-protected-interop',status='PASS',
                    completed_recovery='SELECTED_ASSERTIONS_PASS',pairs=[],restart=[])
        fixtures={name:json.loads((HERE/'fixtures'/file).read_text())['files']
                  for name,file in [('baseline','mcp-protected.json'),('server','mcp-recovery.json')]}
        for mode in ('baseline','server','client'):
            for pair in PAIRS:
                d=root/pair if mode=='baseline' else root/('reopen-'+mode)/pair
                d.mkdir(parents=True)
                for name,raw in fixtures['server' if mode=='server' else 'baseline'].items():
                    (d/name).write_text(raw)
                if mode=='server':
                    # Fixture runs have distinct outer sessions but the same committed result.
                    original=root/pair/'server.journal'
                    (d/'server.journal').write_bytes(original.read_bytes())
                    (d/'server.journal.before').write_bytes(original.read_bytes())
                    lines=(d/'client.journal').read_text().splitlines()
                    terminal=json.loads(lines[-1]);terminal['result_hex']=json.loads(original.read_text().splitlines()[-1])['result_hex']
                    lines[-1]=json.dumps(terminal);(d/'client.journal').write_text('\n'.join(lines)+'\n')
                if mode=='client':
                    for name in ('server.journal','client.journal'):
                        (d/(name+'.before')).write_bytes((d/name).read_bytes())
                    (d/'client.json').write_text(json.dumps(dict(role='client',state='READY',reopen_denied=True)))
                    (d/'server.json').write_text(json.dumps(dict(role='server',state='READY',effects=0)))
                    f=json.loads((d/'frames.json').read_text())
                    f={k:v[:4] for k,v in f.items()};(d/'frames.json').write_text(json.dumps(f))
                left,right=pair.split('-to-')
                for language,role in ((left,'client'),(right,'server')):
                    name=TESTS[language]
                    log=(f'=== RUN   {name}\n--- PASS: {name} (0.01s)\nPASS\n' if language=='go'
                         else f'test {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 filtered out;\n')
                    (d/(role+'.log')).write_text(log)
                frames=json.loads((d/'frames.json').read_text())
                q=[bytes.fromhex(x) for x in frames['requests']];w=[bytes.fromhex(x) for x in frames['responses']]
                checked=setup(q[:4],w[:4])
                checked.update(validate(d,q,w,checked) if mode=='baseline' else validate_recovery(d,q,w,checked,mode))
                row=dict(pair=pair,status='PASS',exit_codes=[0,0],**checked)
                row['files']={p.name:digest(p) for p in d.iterdir()}
                report['pairs' if mode=='baseline' else 'restart'].append(row)
        (root/'report.json').write_text(json.dumps(report))

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'evidence';shutil.copytree(self.template.name,self.root)
        self.report=json.loads((self.root/'report.json').read_text())

    def save(self):
        (self.root/'report.json').write_text(json.dumps(self.report))

    def test_saved_evidence_recomputed(self):
        self.assertEqual(len(audit(self.root)['checks']),12)

    def test_missing_or_duplicate_pair_rejected(self):
        for key in ('pairs','restart'):
            original=copy.deepcopy(self.report[key]);self.report[key][-1]=self.report[key][0];self.save()
            with self.assertRaisesRegex(ValueError,'inventory'):audit(self.root)
            self.report[key]=original

    def test_hash_mismatch_rejected(self):
        (self.root/PAIRS[0]/'client.journal').write_text('changed')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):audit(self.root)

    def test_false_report_claim_rejected(self):
        self.report['pairs'][0]['effects']=0;self.save()
        with self.assertRaisesRegex(ValueError,'reported observation'):audit(self.root)

    def test_failed_process_and_incorrect_observation_type_rejected(self):
        self.report['pairs'][0]['exit_codes']=[0,1];self.save()
        with self.assertRaisesRegex(ValueError,'execution failed'):audit(self.root)
        self.report['pairs'][0]['exit_codes']=[0,0]
        self.report['pairs'][0]['effects']=True;self.save()
        with self.assertRaisesRegex(ValueError,'reported observation'):audit(self.root)

    def test_rehashed_log_cannot_hide_missing_execution(self):
        row=self.report['pairs'][0];p=self.root/row['pair']/'client.log';p.write_text('PASS\n')
        row['files']['client.log']=digest(p);self.save()
        with self.assertRaisesRegex(ValueError,'exact bridge'):audit(self.root)

    def test_rehashed_recovery_copy_must_match_baseline(self):
        row=self.report['restart'][0];p=self.root/'reopen-server'/row['pair']/'server.journal.before'
        p.write_bytes(p.read_bytes()+b'\n');row['files'][p.name]=digest(p);self.save()
        with self.assertRaisesRegex(ValueError,'differs from baseline'):audit(self.root)

    def test_missing_required_hash_and_path_traversal_rejected(self):
        row=self.report['pairs'][0];original=copy.deepcopy(row['files'])
        del row['files']['frames.json'];self.save()
        with self.assertRaisesRegex(ValueError,'missing evidence hash'):audit(self.root)
        row['files']=original;row['files']['../outside']='0'*64;self.save()
        with self.assertRaisesRegex(ValueError,'unsafe evidence name'):audit(self.root)

    def test_cli_success_failure_and_optimized_python(self):
        cmd=[sys.executable,'-B',str(HERE/'audit_mcp_evidence.py'),'--evidence',str(self.root)]
        for optimized in (False,True):
            run=subprocess.run(cmd[:1]+(['-O'] if optimized else [])+cmd[1:],capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,1 if optimized else 0)
            self.assertEqual(json.loads(run.stdout)['status'],'FAIL' if optimized else 'PASS')
        self.report['status']='FAIL';self.save()
        run=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,1)
        self.assertEqual(json.loads(run.stdout)['status'],'FAIL')


if __name__=='__main__':unittest.main()
