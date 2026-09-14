import copy,json,shutil,tempfile,unittest,hashlib
from unittest import mock
from types import SimpleNamespace
from pathlib import Path
from check_deployment_evidence import validate_exchange,check,ROOT
from inspect_host import inspect,inventory

class DeploymentTests(unittest.TestCase):
 def test_archived_evidence(self):check()
 def test_exchange_corruptions(self):
  report=json.loads((ROOT/'docs/evidence/deployment/exchange.json').read_text())
  for kind in ('missing','duplicate','promote','bytes','positive','same-binary'):
   with self.subTest(kind=kind):
    r=copy.deepcopy(report)
    if kind=='missing':r['exchanges'].pop()
    if kind=='duplicate':r['exchanges'][1]=r['exchanges'][0]
    if kind=='promote':r['exchanges'][0]['checks'][-1]['status']='PASS'
    if kind=='bytes':r['exchanges'][0]['checks'][0]['request']['input']['record_hex']='00'
    if kind=='positive':r['exchanges'][0]['checks'][1]['positive_control']='FAIL'
    if kind=='same-binary':r['subjects'][1]['executable_sha256']=r['subjects'][0]['executable_sha256']
    with self.assertRaises(ValueError):validate_exchange(r)
 def test_no_host_means_not_run(self):
  with tempfile.TemporaryDirectory() as tmp:
   report=inspect(ROOT,Path(tmp)/'host')
   self.assertEqual(report['status'],'INCOMPLETE');self.assertEqual(len(report['scenarios']),8)
   self.assertTrue(all(s['status']=='NOT_RUN' and s['observed_effects'] is None for s in report['scenarios']))
   with self.assertRaises(ValueError):inspect(ROOT,Path(tmp)/'host')
   with self.assertRaises(ValueError):inspect(ROOT,Path(tmp)/'partial',runner=Path('/bin/false'))
 def test_bound_host_reports_require_real_effect_fields(self):
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp)
   adapter=base/'adapter';adapter.write_bytes(b'adapter test identity')
   runner=base/'runner';runner.write_bytes(b'runner test identity')
   host=base/'host';host.write_bytes(b'host test identity')
   witness=base/'witness';witness.write_bytes(b'external witness test identity')
   config=base/'config';config.write_bytes(b'test configuration')
   binding=base/'binding.json';binding.write_text(json.dumps(dict(name='synthetic-test-only',version='test',revision='test',isolation='synthetic',witness_boundary='synthetic external witness',host_executable=str(host),host_configuration=str(config),witness_executable=str(witness))))
   for corrupt in (False,True):
    def fake_run(args,**kwargs):
     raw=Path(args[args.index('-scenario')+1]).read_bytes();fixture=json.loads(raw)
     report=dict(schema_version=2,protocol_version='0.10.0',profile='stateful-scenario',case_id=fixture['id'],fixture_sha256=hashlib.sha256(raw).hexdigest(),status='PASS',environment='synthetic',created='2026-09-14T00:00:00Z',sources=fixture['sources'],subject=dict(name='synthetic-test-only',revision='test',kind='external',executable_sha256=hashlib.sha256(adapter.read_bytes()).hexdigest()),steps=[])
     for step in fixture['steps']:
      report['steps'].append(dict(step_id=step['id'],input=step['input'],expected=step['expected'],expected_effects=step['effects'],status='PASS',actual=dict(schema_version=2,case_id=fixture['id'],step_id=step['id'],**step['expected'],effects=copy.deepcopy(step['effects']))))
     if corrupt:report['steps'][2]['actual']['effects']['protected_file_writes']+=1
     kwargs['stdout'].write(json.dumps(report).encode())
     return SimpleNamespace(returncode=0)
    with mock.patch('inspect_host.platform.platform',return_value='synthetic'), mock.patch('inspect_host.subprocess.run',side_effect=fake_run):
     if corrupt:
      with self.assertRaises(ValueError):inspect(ROOT,base/'corrupt',runner,adapter,binding)
     else:
      report=inspect(ROOT,base/'valid',runner,adapter,binding)
      self.assertEqual(report['status'],'PASS');self.assertEqual(report['conformance'],'NOT_ESTABLISHED')
      self.assertEqual(report['scenarios'][0]['observed_effects'][2]['effects']['protected_dispatch'],1)
 def test_fixture_integrity(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'vectors').mkdir();shutil.copytree(ROOT/'vectors/0.10.0',root/'vectors/0.10.0')
   inventory(root)
   fixture=root/'vectors/0.10.0/host-scenarios/host-hook-missing.json'
   fixture.write_text('{}')
   with self.assertRaises(ValueError):inventory(root)
if __name__=='__main__':unittest.main()
