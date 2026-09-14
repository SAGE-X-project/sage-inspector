import copy,json,unittest
from check_concurrent_evidence import ROOT,check,validate

class ConcurrentEvidenceTests(unittest.TestCase):
 def test_live_archive(self):
  r=check();self.assertEqual(r['check_counts'],{'PASS':224,'FAIL':0,'INCOMPLETE':0,'NOT_RUN':0});self.assertEqual(r['observed_workers'],512);self.assertEqual(r['conformance'],'NOT_ESTABLISHED')
 def test_mutations(self):
  original=json.loads((ROOT/'docs/evidence/deployment/concurrent.json').read_text())
  for kind in ('missing-round','duplicate-batch','double-accept','invalid-accept','serial','ready','index','input','count'):
   with self.subTest(kind=kind):
    r=copy.deepcopy(original);b=r['batches'][0];round=b['rounds'][0];group=round['reception']['actual']['output']['results'][0]['output']
    workers=group['workers'];winner=next(w for w in workers if w['verdict']=='ACCEPT');loser=next(w for w in workers[:4] if w['verdict']=='REJECT')
    if kind=='missing-round':b['rounds'].pop()
    if kind=='duplicate-batch':r['batches'][1]=b
    if kind=='double-accept':loser.update(verdict='ACCEPT',output=winner['output'])
    if kind=='invalid-accept':workers[4].update(verdict='ACCEPT',output=winner['output'])
    if kind=='serial':
     for i,w in enumerate(workers):w.update(started_ns=i*100+1,finished_ns=i*100+10)
    if kind=='ready':group['workers_ready']=7
    if kind=='index':workers[1]['index']=0
    if kind=='input':round['reception']['request']['input']['actions'][0]['records_hex'][0]='00'
    if kind=='count':r['check_counts']['PASS']=225
    with self.assertRaises(ValueError):validate(r)
 def test_no_overlap_is_incomplete_not_core_failure(self):
  r=json.loads((ROOT/'docs/evidence/deployment/concurrent.json').read_text());round=r['batches'][0]['rounds'][0]
  for i,w in enumerate(round['reception']['actual']['output']['results'][0]['output']['workers']):w.update(started_ns=i*100+1,finished_ns=i*100+10)
  round['call_interval_overlap'][0]=False;round['check_statuses'][0]='INCOMPLETE';r['check_counts']['PASS']-=1;r['check_counts']['INCOMPLETE']+=1;r['status']='INCOMPLETE'
  self.assertEqual(validate(r)['INCOMPLETE'],1)
if __name__=='__main__':unittest.main()
