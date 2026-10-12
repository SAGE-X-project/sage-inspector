"""Synthetic admission tests are separate from native library observations."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from a2a_card_observation import ROOT, FIXTURE_PATH, fixtures, assess, run_native, main

class ObservationTests(unittest.TestCase):
    def test_missing_observations_do_not_pass(self):
        report=assess([])
        self.assertEqual(len(report['cases']),583)
        self.assertTrue(all(c['status']=='NOT_RUN' for c in report['cases']))
        self.assertEqual(report['conformance'],'NOT_ESTABLISHED')

    def test_all_matching_synthetic_outputs_remain_partial(self):
        rows=[{'id':c['id'],'input_sha256':c['input_sha256'],'actual':c['expected']} for c in fixtures()]
        report=assess(rows)
        self.assertEqual(sum(c['status']=='PARTIAL' for c in report['cases']),41)
        self.assertEqual(sum(c['status']=='NOT_RUN' for c in report['cases']),542)
        self.assertNotIn('PASS',{c['status'] for c in report['cases']})
        self.assertEqual(report['evidence_kind'],'reported-library-output')

    def test_shape_hash_identity_and_mismatches(self):
        c=fixtures()[0];row={'id':c['id'],'input_sha256':c['input_sha256'],'actual':c['expected']}
        for mutation in ('hash','unknown','duplicate','self-pass','wrong-type','extra-field'):
            r=copy.deepcopy(row);rows=[r]
            if mutation=='hash':r['input_sha256']='0'*64
            elif mutation=='unknown':r['id']='unknown'
            elif mutation=='duplicate':rows.append(r)
            elif mutation=='self-pass':r['status']='PASS'
            elif mutation=='wrong-type':r['actual']['accepted']=1
            else:r['actual']['uninspected']=True
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):assess(rows)
        r=copy.deepcopy(row);r['actual']['interfaces']=[]
        self.assertEqual(next(x['status'] for x in assess([r])['cases'] if x['id']==r['id']),'FAIL')

    def test_fixture_bytes_are_pinned(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/FIXTURE_PATH;p.parent.mkdir(parents=True);shutil.copy(ROOT/FIXTURE_PATH,p)
            p.write_bytes(p.read_bytes()+b' ')
            with self.assertRaisesRegex(ValueError,'fixture drift'):fixtures(root)

    def test_cli_inventory_and_error(self):
        import sys
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'report.json'
            with patch.object(sys,'argv',['observe','--output',str(p)]):main()
            self.assertEqual(json.loads(p.read_bytes())['conformance'],'NOT_ESTABLISHED')
            with patch.object(sys,'argv',['observe','--output',str(p/'missing')]),self.assertRaises(SystemExit) as e:main()
            self.assertEqual(e.exception.code,1)

if __name__=='__main__':unittest.main()
