from pathlib import Path
import json,hashlib,copy
root=Path(__file__).resolve().parents[2]
src=root/'sage-inspector/vectors/0.10.0/hpke-schedule.json'
source=json.loads(src.read_text())
def raw(m):return json.dumps(m,sort_keys=True,separators=(',',':')).encode()
cases=[]
def add(id,op,data,expected=None):cases.append(dict(id=id,operation=op,input=data,expected=expected))
for c in source['cases'][:3]:
 o=c['expected']['output'];i=c['input'];name=c['id']
 dom={k:o[k] for k in ['binding_hex','info_hex','export_context_hex']}
 out={k:o[k] for k in ['transcript_hex','th_hex','seed_hex','ack_tag_hex','sid']}
 add(name+'-domains','domains',dict(binding_hex=o['binding_hex']),dom)
 add(name+'-responder','respond',dict(initiation_hex=o['initiation_hex'],kem_private_hex=i['recipient_private_hex'],e2e_private_hex=i['server_ephemeral_private_hex'],kid=i['kid']),out)
base=copy.deepcopy(cases[1]);init=bytes.fromhex(base['input']['initiation_hex']);m=json.loads(init)
b=copy.deepcopy(cases[0]);binding=bytes.fromhex(b['input']['binding_hex'])
mutations={'v':'v1','suite':'other','combiner':'other','ctx':'11111111-1111-1111-8111-111111111111','nonce':'AA','initDid':'did:sage:solana:abc:alice','respDid':'did:sage:web:127.0.0.1:bob','initKid':m['respKid'],'respKid':m['initKid'],'kemKid':m['initKid'],'task':'hpke/init@v1','enc':'AA','ephC':'AA'}
for k,v in mutations.items():
 n=dict(m,**{k:v});add('invalid-'+k,'respond',dict(base['input'],initiation_hex=raw(n).hex()))
for k in ['enc','ephC']:
 for value in [bytes(32),b'\x01'+bytes(31)]:
  import base64
  n=dict(m,**{k:base64.urlsafe_b64encode(value).decode().rstrip('=')});add('low-order-'+k+'-'+str(value[0]),'respond',dict(base['input'],initiation_hex=raw(n).hex()))
for k in m:
 n=dict(m);n.pop(k);add('missing-'+k,'respond',dict(base['input'],initiation_hex=raw(n).hex()))
for name,value in [('extra',dict(m,unexpected='value')),('null',dict(m,v=None)),('array',dict(m,v=[])),('number',dict(m,v=10)),('case',dict(m,V=m['v'])),('unicode',dict(m,nonce='é'))]:add(name,'respond',dict(base['input'],initiation_hex=raw(value).hex()))
for name,value in [('duplicate',init[:-1]+b',"v":"0.10.0"}'),('trailing',init+b' {}'),('utf8',b'{"v":"\xff"}'),('root-null',b'null'),('root-array',b'[]'),('oversized',init+b' '*(16385-len(init)))]:add(name,'respond',dict(base['input'],initiation_hex=value.hex()))
add('size-16384','respond',dict(base['input'],initiation_hex=(init+b' '*(16384-len(init))).hex()),base['expected'])
for k in ['kem_private_hex','e2e_private_hex']:
 for n in [0,31,33]:add(k+'-'+str(n),'respond',dict(base['input'],**{k:'01'*n}))
add('invalid-kid','respond',dict(base['input'],kid='kid-legacy'))
# The closed binding API must reject extras, duplicates, wrong values and trailing JSON too.
for name,value in [('extra',binding[:-1]+b',"extra":"x"}'),('duplicate',binding[:-1]+b',"v":"0.10.0"}'),('trailing',binding+b' {}'),('old-version',binding.replace(b'0.10.0',b'v1'))]:add('binding-'+name,'domains',dict(binding_hex=value.hex()))
fixture=dict(source_revision='454f68f96b7b59fbe7b209fa298f6adbf59554fd',source_path='vectors/0.10.0/hpke-schedule.json',source_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),scope='Public fixed domains and responder cryptographic derivation; no signatures or authority',cases=cases)
path=root/'sage-inspector/vectors/0.10.0/hpke-derivation010.json'
encoded=json.dumps(fixture,indent=2)+'\n'
import sys
if '--check' in sys.argv:
    assert path.read_text()==encoded, 'derivation fixture drift'
else:
    path.write_text(encoded)
print(len(cases),'cases')
