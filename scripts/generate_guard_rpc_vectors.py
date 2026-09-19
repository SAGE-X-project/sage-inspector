"""Independent closed RPC cases from frozen public intent/result fixtures."""
import copy,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def wire(x):return json.dumps(x,ensure_ascii=False,separators=(',',':'),sort_keys=True)
def generate():
 v=json.loads((ROOT/'vectors/0.10.0/guard-client.json').read_text());id='00000000-0000-4000-8000-000000000101';other='00000000-0000-4000-8000-000000000102'
 intent=json.loads(bytes.fromhex(v['input']['envelope_hex']));result=json.loads(bytes.fromhex(v['results']['completed']))
 request=dict(jsonrpc='2.0',id=id,method='tools/call',params=dict(name='sage_secure_call',arguments=dict(envelope=intent)))
 mcp=dict(structuredContent=result,content=[dict(type='text',text=wire(result))],isError=False)
 response=dict(jsonrpc='2.0',id=id,result=mcp)
 suite=dict(kind='guard-mcp-rpc',id=id,input=v['input'],public_key_hex=v['public_key_hex'],result_hex=v['results']['completed'],requests=[],responses=[])
 def add(side,name,obj,version='2025-06-18',parse=False,accept=False,raw=None):suite[side].append(dict(id=name,version=version,wire_hex=(wire(obj) if raw is None else raw).encode().hex(),parse=parse,accept=accept))
 add('requests','valid',request,parse=True,accept=True)
 for name in ['notification','batch','null-id','numeric-id','wrong-id','wrong-jsonrpc','missing-jsonrpc','other-method','direct-tool','extra-param','extra-argument','missing-envelope','null-envelope','extra-root','unsigned-meta','extra-envelope','recursive-tool','bad-proof','rounded-time','fractional-time','duplicate-id','duplicate-envelope','trailing-json']:
  q=copy.deepcopy(request)
  if name=='notification':del q['id']
  if name=='batch':q=[q]
  if name=='null-id':q['id']=None
  if name=='numeric-id':q['id']=101
  if name=='wrong-id':q['id']=other
  if name=='wrong-jsonrpc':q['jsonrpc']='1.0'
  if name=='missing-jsonrpc':del q['jsonrpc']
  if name=='other-method':q['method']='read'
  if name=='direct-tool':q['params']['name']='read'
  if name=='extra-param':q['params']['tool']='read'
  if name=='extra-argument':q['params']['arguments']['path']='other'
  if name=='missing-envelope':q['params']['arguments']={}
  if name=='null-envelope':q['params']['arguments']['envelope']=None
  if name=='extra-root':q['tool']='read'
  if name=='unsigned-meta':q['params']['_meta']={'note':'unsigned'}
  if name=='extra-envelope':q['params']['arguments']['envelope']['note']='unsigned'
  if name=='recursive-tool':q['params']['arguments']['envelope']['intent']['tool']='sage_secure_call'
  if name=='bad-proof':q['params']['arguments']['envelope']['proof']='A'*86
  raw=wire(q)
  if name in ['rounded-time','fractional-time']:raw=raw.replace('"created":1700000000','"created":1700000000.000000001' if name=='rounded-time' else '"created":1700000000.5')
  if name=='duplicate-id':raw=raw[:-1]+',"i\\u0064":'+wire(id)+'}'
  if name=='duplicate-envelope':raw=raw.replace('"envelope":','"envelope":{},"envelope":',1)
  if name=='trailing-json':raw+='{}'
  add('requests',name,q,raw=raw,parse=name=='bad-proof')
 for version in ['', '2024-11-05','2025-06-19']:add('requests','unsupported-'+repr(version),request,version=version)
 add('responses','valid',response,parse=True,accept=True)
 for name in ['wrong-id','null-id','numeric-id','missing-id','missing-jsonrpc','wrong-jsonrpc','batch','rpc-error','error-and-result','extra-root','missing-result','null-result','extra-block','mismatch','wrong-flag','bad-proof','duplicate-id','trailing-json']:
  q=copy.deepcopy(response)
  if name=='wrong-id':q['id']=other
  if name=='null-id':q['id']=None
  if name=='numeric-id':q['id']=101
  if name=='missing-id':del q['id']
  if name=='missing-jsonrpc':del q['jsonrpc']
  if name=='wrong-jsonrpc':q['jsonrpc']='1.0'
  if name=='batch':q=[q]
  if name=='rpc-error':q.pop('result');q['error']={'code':-32603,'message':'unverified'}
  if name=='error-and-result':q['error']={'code':-32603,'message':'unverified'}
  if name=='extra-root':q['_meta']={}
  if name=='missing-result':q.pop('result')
  if name=='null-result':q['result']=None
  if name=='extra-block':q['result']['content'].append({'type':'text','text':'unsigned'})
  if name=='mismatch':q['result']['content'][0]['text']='{}'
  if name=='wrong-flag':q['result']['isError']=True
  if name=='bad-proof':q['result']['structuredContent']['proof']='A'*86;q['result']['content'][0]['text']=wire(q['result']['structuredContent'])
  raw=wire(q)
  if name=='duplicate-id':raw=raw[:-1]+',"i\\u0064":'+wire(id)+'}'
  if name=='trailing-json':raw+='{}'
  add('responses',name,q,raw=raw,parse=name=='bad-proof')
 for version in ['', '2024-11-05','2025-06-19']:add('responses','unsupported-'+repr(version),response,version=version)
 return json.dumps(suite,indent=2)+'\n'
if __name__=='__main__':
 raw=generate();target=ROOT/'vectors/0.10.0/guard-rpc.json'
 if '--check' in sys.argv:assert target.read_text()==raw
 else:target.write_text(raw)
 print('RPC fixture verified')
