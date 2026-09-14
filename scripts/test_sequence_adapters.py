"""Operator-selected real adapters: malformed batch controls must be process errors."""
import copy,json,subprocess,sys
from pathlib import Path
report=json.loads((Path(__file__).resolve().parents[1]/'docs/evidence/deployment/replay.json').read_text())
for adapter in sys.argv[1:]:
 for stage in ('production','reception'):
  q=report['trials'][0][stage]['request']
  mutations=[('seed_hex',None),('seed_hex','00'),('sid',None),('direction','bad'),('caller_aad_hex',None)]
  if stage=='production':mutations += [('messages_hex',[]),('messages_hex',['61']*17),('messages_hex',['61'*513])]
  else:mutations += [('actions',[]),('actions',[{'kind':'close'}]*33),('actions',[{'kind':'open','record_hex':'zz'}]),('actions',[{'kind':'bogus'}])]
  for key,value in mutations:
   altered=copy.deepcopy(q);altered['input'][key]=value
   p=subprocess.run([adapter],input=json.dumps(altered),text=True,capture_output=True,timeout=10)
   assert p.returncode!=0 and not p.stdout,(adapter,key,p.stdout)
 print(adapter+': malformed sequence controls remain adapter errors')
