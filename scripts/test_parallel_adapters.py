"""Malformed parallel controls remain process errors in the real adapters."""
import copy,json,subprocess,sys
from pathlib import Path
r=json.loads((Path(__file__).resolve().parents[1]/'docs/evidence/deployment/concurrent.json').read_text())
q=r['batches'][0]['rounds'][0]['reception']['request']
for executable in sys.argv[1:]:
 for records in (None,[],['00'],['00']*17,['zz','00'],['00'*2049,'00']):
  request=copy.deepcopy(q);request['input']['actions']=[dict(kind='parallel_open',records_hex=records)]
  p=subprocess.run([executable],input=json.dumps(request),text=True,capture_output=True,timeout=10)
  assert p.returncode!=0 and not p.stdout,(executable,records,p.stdout)
 print(executable+': malformed parallel controls remain adapter errors')
