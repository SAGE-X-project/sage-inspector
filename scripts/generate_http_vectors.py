"""Independent HTTP signature fixtures. No SAGE/reference-project code is imported.
Fixed RFC8032 TEST1 seed is public test material; archived messages omit expiry.
"""
import base64,copy,hashlib,json,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))
pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
url='https://agent.example/call?x=1';did='did:sage:web:agent.example:alice';kid=did+'#signing-1';nonce='AAAAAAAAAAAAAAAAAAAAAA'
reqc=['"@method"','"@target-uri"','"@authority"','"content-type"','"content-digest"','"x-sage-did"','"x-sage-version"']
respc=['"@status"']+[c+';req' for c in ['"@method"','"@target-uri"','"@authority"','"content-digest"','"signature"','"x-sage-version"']]+['"content-type"','"content-digest"','"x-sage-did"','"x-sage-version"']
def digest(body):return 'sha-256=:'+base64.b64encode(hashlib.sha256(body).digest()).decode()+':'
def make(response=False,request=None,strict=False,reorder=False,body=b'{}',target=url):
    start='HTTP/1.1 200 OK' if response else 'POST '+target+' HTTP/1.1'
    h={'Host':'agent.example','Content-Type':'application/json','Content-Digest':digest(body),'X-Sage-Did':did,'X-Sage-Version':'0.10.0','Content-Length':str(len(body))}
    comp=respc if response else reqc
    params=[f'keyid="{kid}"','alg="ed25519"','created=1700000000']
    if strict:params+=['expires=1700000300']
    params += [f'nonce="{nonce}"']
    if strict:params+=['tag="sage-0.10.0"']
    if reorder:params.reverse()
    raw='('+' '.join(comp)+');'+';'.join(params)
    values={'"@method"':'POST','"@target-uri"':target,'"@authority"':'agent.example','"@status"':'200'}
    values.update({'"'+k.lower()+'"':v for k,v in h.items()})
    if response:
        old=request['h'];rv={'"@method"':'POST','"@target-uri"':url,'"@authority"':'agent.example'}
        rv.update({'"'+k.lower()+'"':v for k,v in old.items()})
        values.update({k+';req':v for k,v in rv.items()})
    base='\n'.join(c+': '+values[c] for c in comp)+'\n"@signature-params": '+raw
    signature=key.sign(base.encode());key.public_key().verify(signature,base.encode())
    h['Signature-Input']='sig1='+raw;h['Signature']='sig1=:'+base64.b64encode(signature).decode()+':'
    return {'start':start,'h':h,'body':body,'base':base}
def wire(m):return (m['start']+'\r\n'+''.join(k+': '+v+'\r\n' for k,v in m['h'].items())+'\r\n').encode()+m['body']
cases=[];audit={}
def add(id,op,request,response=None,reject=False,base=None,repeat=1,why='Independently serialize declared components; sign fixed bytes with Python cryptography; mutate only stated field.',rule='MSG-02'):
    rq=wire(request) if isinstance(request,dict) else request
    rp=wire(response) if isinstance(response,dict) else response or b''
    result={} if reject else ({'base_hex':base.encode().hex()} if base is not None else {'valid':True})
    cases.append(dict(id=id,operation=op,rule_ids=[rule],source_ids=['rfc9421','rfc9530','sage-http'],derivation=why,input=dict(request_hex=rq.hex(),response_hex=rp.hex(),public_key_hex=pub,body_repeat=repeat),expected=dict(verdict='REJECT' if reject else 'ACCEPT',output=result)))
    actual=rq
    if repeat>1:pos=rq.index(b'\r\n\r\n')+4;actual=rq[:pos]+rq[pos:]*repeat
    audit[id]={'request_sha256':hashlib.sha256(actual).hexdigest(),'request_bytes':len(actual),'response_sha256':hashlib.sha256(rp).hexdigest(),'response_bytes':len(rp)}
a=make();b=make(True,a);full=make(strict=True);fullresp=make(True,full,strict=True)
for label,m,r in [('request',a,None),('response',a,b),('sage-request',full,None),('sage-response',full,fullresp),('reordered-request',make(reorder=True),None)]:
    add('base-'+label,'rfc9421.base',m,r,base=(r or m)['base'],rule='MSG-03' if r else 'MSG-01')
escaped=make(target='https://agent.example/a%2fb?x=%2f')
add('base-escaped-target','rfc9421.base',escaped,base=escaped['base'])
add('base-missing-request','rfc9421.base',b'',b,reject=True,rule='MSG-03')
# Signature verification is explicitly archival, not SAGE freshness certification.
add('archive-request','rfc9421.archived.verify',a)
add('archive-response','rfc9421.archived.verify',a,b,rule='MSG-03')
add('archive-reordered','rfc9421.archived.verify',make(reorder=True),rule='MSG-01')
for name,mut in [('body',lambda m:m.update(body=b'{ }')),('target',lambda m:m.update(start=m['start'].replace('/call?','/other?'))),('content-type',lambda m:m['h'].update({'Content-Type':'text/plain'})),('did',lambda m:m['h'].update({'X-Sage-Did':did+'x'})),('version',lambda m:m['h'].update({'X-Sage-Version':'0.9.0'})),('signature',lambda m:m['h'].update({'Signature':'sig1=:'+base64.b64encode(bytes(64)).decode()+':'}))]:
    m=copy.deepcopy(a);mut(m)
    if name=='body':m['h']['Content-Length']=str(len(m['body']))
    add('archive-tamper-'+name,'rfc9421.archived.verify',m,reject=True)
m=copy.deepcopy(a);m['h']['Signature-Input']+=';tag="attacker-domain"';add('archive-added-tag','rfc9421.archived.verify',m,reject=True,rule='MSG-01')
m=copy.deepcopy(a);m['h']['Forwarded']='host=attacker.example;proto=http';m['h']['X-Forwarded-Host']='attacker.example'
add('archive-forwarded-ignored','rfc9421.archived.verify',m)
for name in ['signature','target','body-digest']:
    m=copy.deepcopy(a)
    if name=='signature':m['h']['Signature']='sig1=:AAAA:'
    elif name=='target':m['start']=m['start'].replace('/call?','/other?')
    else:m['h']['Content-Digest']=digest(b'changed')
    add('archive-response-wrong-request-'+name,'rfc9421.archived.verify',m,b,reject=True,rule='MSG-03')
add('archive-response-missing-request','rfc9421.archived.verify',b'',b,reject=True,rule='MSG-03')
m=copy.deepcopy(b);m['start']='HTTP/1.1 201 Created';add('archive-response-status','rfc9421.archived.verify',a,m,reject=True,rule='MSG-03')
m=copy.deepcopy(b);m['body']=b'{ }';m['h']['Content-Length']='3';add('archive-response-body','rfc9421.archived.verify',a,m,reject=True,rule='MSG-03')
m=copy.deepcopy(a);m['h'].pop('Signature');add('archive-unsigned','rfc9421.archived.verify',m,reject=True)
# SAGE Content-Digest projection, with a positive control and isolated mutations.
add('digest-valid','sage.content-digest',a,rule='MSG-01')
for name,header in [('wrong',digest(b'other')),('other-algorithm','sha-512=:AAAA:'),('additional-member',a['h']['Content-Digest']+', sha-512=:AAAA:'),('duplicate-member',a['h']['Content-Digest']+', '+a['h']['Content-Digest']),('unpadded','sha-256=:'+base64.b64encode(hashlib.sha256(b'{}').digest()).decode().rstrip('=')+':')]:
    m=copy.deepcopy(a);m['h']['Content-Digest']=header;add('digest-'+name,'sage.content-digest',m,reject=True,rule='MSG-01')
m=copy.deepcopy(a);m['body']=b'{ }';m['h']['Content-Length']='3';add('digest-raw-whitespace','sage.content-digest',m,reject=True,rule='MSG-01')
raw=wire(a).replace(('Content-Digest: '+a['h']['Content-Digest']+'\r\n').encode(),(('Content-Digest: '+a['h']['Content-Digest']+'\r\n')*2).encode())
add('digest-duplicate-field','sage.content-digest',raw,reject=True,rule='MSG-04')
for n in [16<<20,(16<<20)+1]:
    m=make(body=b'x');m['h']['Content-Length']=str(n);m['h']['Content-Digest']=digest(b'x'*n)
    add('digest-body-'+str(n),'sage.content-digest',m,repeat=n,reject=n>(16<<20),rule='MSG-04',why='Compact body recipe expands one x byte to exact boundary length. Digest independently computed over all expanded bytes; no HTTP signature or JSON schema claim.')
# Boundary cases stay explicitly unsupported until complete timed HTTP APIs exist.
for name,raw in [('duplicate-content-type',wire(full).replace(b'Content-Type: application/json\r\n',b'Content-Type: application/json\r\nContent-Type: application/json\r\n')),('conflicting-length',wire(full).replace(b'Content-Length: 2',b'Content-Length: 3')),('transfer-and-length',wire(full).replace(b'Content-Length: 2',b'Transfer-Encoding: chunked\r\nContent-Length: 2')),('fields-over-32k',wire(full).replace(b'Host: agent.example',b'X-Padding: '+b'x'*32769+b'\r\nHost: agent.example')),('expired',wire(full)),('wrong-tag',wire(full).replace(b'sage-0.10.0',b'sage-0.9.0'))]:
    add('boundary-'+name,'sage.http.verify',raw,reject=True,rule='MSG-04',why='Planned SAGE boundary rejection; no fixed-clock/full-boundary binding in either current core adapter. Must report UNSUPPORTED, never infer acceptance from archival checks.')
for c in cases:
    if c['operation']=='sage.http.verify':c['input']['now_unix']=1700000330 if c['id']=='boundary-expired' else 1700000001
# The local reference's missing signature-params/legacy target informed base regressions.
sources=[dict(id='rfc9421',kind='spec-derived',uri='https://www.rfc-editor.org/rfc/rfc9421.html',reference='Sections2.3-2.5 and3.2: explicit ordered bases and request-bound response components; synthetic messages, not copied RFC signature values.'),dict(id='rfc9530',kind='spec-derived',uri='https://www.rfc-editor.org/rfc/rfc9530.html',reference='Content-Digest over exact received content bytes; digest computed independently by hashlib.'),dict(id='sage-http',kind='spec-derived',uri='sage-spec/spec/03-rfc9421.md',reference='Pinned MSG-01..04 profile restrictions; archival operation deliberately does not certify full SAGE profile or freshness.')]
suite=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',id='sage-http-signatures-0.10.0',sources=sources,cases=cases)
root=Path(__file__).resolve().parents[1]
out=Path(sys.argv[1]) if len(sys.argv)>1 else root/'vectors/0.10.0/http-signatures.json'
out.write_text(json.dumps(suite,indent=2)+'\n')
if len(sys.argv)>2:Path(sys.argv[2]).write_text(json.dumps(audit,indent=2)+'\n')
print(len(cases),'cases',out)
