import copy,json,unittest
from check_replay_evidence import ROOT,check,validate

class ReplayEvidenceTests(unittest.TestCase):
 def test_archived_live_run(self):
  r=check();self.assertEqual(r['action_counts'],{'PASS':36,'FAIL':0,'UNSUPPORTED':0,'NOT_RUN':0});self.assertEqual(r['conformance'],'NOT_ESTABLISHED')
 def test_mutations(self):
  original=json.loads((ROOT/'docs/evidence/deployment/replay.json').read_text())
  for kind in ('missing','duplicate','replay','close','plaintext','control','request','expectation','counts','subject'):
   with self.subTest(kind=kind):
    r=copy.deepcopy(original);t=r['trials'][0]
    if kind=='missing':r['trials'].pop()
    if kind=='duplicate':r['trials'][1]=t
    if kind=='replay':t['reception']['actual']['output']['results'][1]=t['reception']['actual']['output']['results'][0]
    if kind=='close':t['reception']['actual']['output']['results'][-1]['verdict']='ACCEPT'
    if kind=='plaintext':t['reception']['actual']['output']['results'][3]['output']['plaintext_hex']='00'
    if kind=='control':t['fresh_record_control']['actual']['output']['results'][0]['output']['plaintext_hex']='00'
    if kind=='request':t['reception']['request']['input']['actions'][1]['record_hex']='00'
    if kind=='expectation':t['expected_actions'][1]['verdict']='ACCEPT'
    if kind=='counts':r['action_counts']['PASS']=37
    if kind=='subject':r['subjects'][1]['executable_sha256']=r['subjects'][0]['executable_sha256']
    with self.assertRaises(ValueError):validate(r)
if __name__=='__main__':unittest.main()
