"""Corruption tests for independent vectors, report membership and adapter errors."""
import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from inspect_hpke import ROOT, validate_report


class HPKEInspectionTests(unittest.TestCase):
    def test_audit_rejects_changed_middle_or_expected_value(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory)
            source=ROOT/'vectors/0.10.0'
            for name in ['hpke-primitives.json','hpke-schedule.json','hpke-rejection-reasons.json']:
                shutil.copyfile(source/name,directory/name)
            shutil.copytree(source/'hpke-scenarios',directory/'hpke-scenarios')
            def run():
                return subprocess.run(['node',str(ROOT/'scripts/check_hpke_vectors.js'),str(directory)],capture_output=True,text=True,timeout=10)
            self.assertEqual(run().returncode,0)
            suite=json.loads((directory/'hpke-schedule.json').read_text())
            original=copy.deepcopy(suite)
            for field in ['binding_hex','info_hex','export_context_hex','exporter_hex','ss_e2e_hex','transcript_hex','th_hex','prk_hex','seed_hex','ack_key_hex','ack_tag_hex','sid']:
                changed=copy.deepcopy(original)
                changed['cases'][0]['expected']['output'][field]='00'
                (directory/'hpke-schedule.json').write_text(json.dumps(changed))
                self.assertNotEqual(run().returncode,0,field)
            (directory/'hpke-schedule.json').write_text(json.dumps(original))
            changed=copy.deepcopy(original)
            changed['cases'][0]['input']['binding']['ctx']='changed'
            (directory/'hpke-schedule.json').write_text(json.dumps(changed))
            self.assertNotEqual(run().returncode,0)
            changed=copy.deepcopy(original)
            changed['cases'][0]['input']['responder_signing_private_hex']='00'*32
            (directory/'hpke-schedule.json').write_text(json.dumps(changed))
            self.assertNotEqual(run().returncode,0)

    def test_reports_do_not_promote_missing_or_unsupported(self):
        raw=(ROOT/'vectors/0.10.0/hpke-primitives.json').read_bytes()
        report=json.loads((ROOT/'docs/evidence/hpke/go/hpke-primitives.json').read_text())
        validate_report(raw,report)
        for mutation in ['missing','duplicate','hash','counts','promoted']:
            changed=copy.deepcopy(report)
            if mutation=='missing':
                changed['results'].pop()
            elif mutation=='duplicate':
                changed['results'][1]=changed['results'][0]
            elif mutation=='hash':
                changed['suite_sha256']='0'*64
            elif mutation=='counts':
                changed['counts']['PASS']+=1
            else:
                next(r for r in changed['results'] if r['status']=='UNSUPPORTED')['status']='PASS'
            with self.assertRaises(ValueError,msg=mutation):
                validate_report(raw,changed)

    def test_runner_failure_is_error_not_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'new-evidence'
            result=subprocess.run([sys.executable,str(ROOT/'scripts/inspect_hpke.py'),'--runner',sys.executable,
                                   '--adapter',sys.executable,'--subject','test','--revision','test','--output-dir',str(out)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertEqual(json.loads((out/'summary.json').read_text())['status'],'ERROR')


if __name__=='__main__':
    unittest.main()
