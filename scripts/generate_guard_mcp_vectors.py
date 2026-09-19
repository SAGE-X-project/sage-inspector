"""Derive wire variants from frozen public fixtures without calling either core."""
from pathlib import Path
import json,copy
i=Path(__file__).resolve().parents[1];cases=json.loads((i/'vectors/0.10.0/guard-records.json').read_text())['cases'];by={c['id']:c for c in cases}
suite={'kind':'guard-mcp-results','scope':'Independent MCP representation and fresh result verification cases; no full lifecycle conformance.','cases':[]}
def j(v):return json.dumps(v,ensure_ascii=False,separators=(',',':'),sort_keys=True)
def add(name,wire,f,version='2025-06-18',ok=False):
 suite['cases'].append(dict(id=name,input=dict(f,wire_hex=wire.encode().hex(),mcp_version=version),accept=ok))
for status in ['completed','pending','rejected','unknown']:
 f=copy.deepcopy(by['result-'+status+'-valid']['input']);e=json.loads(bytes.fromhex(f['envelope_hex']));w={'structuredContent':e,'content':[{'type':'text','text':j(e)}],'isError':status!='completed'}
 add(status,j(w),f,ok=True)
 if status!='completed':continue
 base=copy.deepcopy(w);fixture=copy.deepcopy(f)
for name in ['mismatch','noncanonical','extra-block','annotation','block-annotation','missing-structured','missing-text','missing-flag','null-flag','string-flag','wrong-flag','invalid-proof','unsigned-error','rounded-time','fractional-time','wrong-status']:
 w=copy.deepcopy(base);f=copy.deepcopy(fixture)
 if name=='mismatch':w['content'][0]['text']='{}'
 if name=='noncanonical':w['content'][0]['text']=' '+w['content'][0]['text']
 if name=='extra-block':w['content'].append({'type':'text','text':'ignored'})
 if name=='annotation':w['_meta']={'note':'unsigned'}
 if name=='block-annotation':w['content'][0]['annotations']={}
 if name=='missing-structured':del w['structuredContent']
 if name=='missing-text':w['content']=[]
 if name=='missing-flag':del w['isError']
 if name=='null-flag':w['isError']=None
 if name=='string-flag':w['isError']='false'
 if name=='wrong-flag':w['isError']=True
 if name=='invalid-proof':w['structuredContent']['proof']='A'*86;w['content'][0]['text']=j(w['structuredContent'])
 if name=='unsigned-error':w={'isError':True,'content':[{'type':'text','text':'unavailable'}]}
 if name=='wrong-status':w['structuredContent']['result']['status']='success';w['content'][0]['text']=j(w['structuredContent'])
 wire=j(w)
 if name in ('rounded-time','fractional-time'):
  # Only structured representation changes: text retains the valid signed original.
  wire=wire.replace('"created":1700000000','"created":1700000000.00000000001' if name=='rounded-time' else '"created":1700000000.5')
 add(name,wire,f)
for name,wire in [('duplicate-field',j(base)[:-1]+',"isError":false}'),('duplicate-decoded-field',j(base)[:-1]+',"is\\u0045rror":false}'),('trailing-json',j(base)+'{}'),('invalid-surrogate',j(base).replace('public output','\\ud800'))]:add(name,wire,fixture)
for version in ['', '2024-11-05','2025-06-19','2025-06-18 ']:add('version-'+repr(version),j(base),fixture,version)
for name,field,value in [('expired','now',1700000300),('revoked','active_key',False),('unsolicited','outstanding',False),('clock-untrusted','clock_trusted',False)]:
 f=copy.deepcopy(fixture);f[field]=value;add(name,j(base),f)
raw=json.dumps(suite,indent=2)+'\n'
target=i/'vectors/0.10.0/guard-mcp.json'
import sys
if '--check' in sys.argv:
 assert target.read_text()==raw, 'MCP fixture differs from independent derivation'
else:
 target.write_text(raw)
print(len(suite['cases']))
