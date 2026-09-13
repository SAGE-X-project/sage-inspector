"""Cross-check positive expected bases/signatures from serialized HTTP bytes.
This deliberately small checker handles this fixture grammar, not arbitrary HTTP.
"""
import base64,hashlib,json,re,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def parse(raw):
    if not raw:return None
    head,body=raw.split(b'\r\n\r\n',1);lines=head.decode().split('\r\n');headers={}
    for line in lines[1:]:
        name,value=line.split(':',1);name=name.lower()
        if name in headers:raise ValueError('positive fixture has duplicate field')
        headers[name]=value.strip()
    return lines[0],headers,body

def signature_base(message,request):
    first,headers,_=message
    member=headers['signature-input'].split('=',1)[1]
    components=re.findall(r'"[^"]+"(?:;req)?',member[:member.index(')')+1])
    lines=[]
    for component in components:
        req=component.endswith(';req');src=request if req else message
        if src is None:raise ValueError('missing original request')
        first,h,_=src;name=component.split('"')[1]
        if name=='@method':value=first.split(' ')[0]
        elif name=='@target-uri':value=first.split(' ')[1]
        elif name=='@authority':value=first.split(' ')[1].split('://',1)[1].split('/',1)[0].lower()
        elif name=='@status':value=first.split(' ')[1]
        else:value=h[name]
        lines.append(component+': '+value)
    return ('\n'.join(lines)+'\n"@signature-params": '+member).encode()

suite=json.loads(Path(sys.argv[1]).read_text());count=0
for c in suite['cases']:
    if c['expected']['verdict']!='ACCEPT':continue
    i=c['input'];raw=bytes.fromhex(i['request_hex']);repeat=i['body_repeat']
    if repeat>1:
        h,b=raw.split(b'\r\n\r\n',1);raw=h+b'\r\n\r\n'+b*repeat
    req=parse(raw);resp=parse(bytes.fromhex(i['response_hex']));message=resp or req
    op=c['operation']
    if op=='rfc9421.base':assert signature_base(message,req).hex()==c['expected']['output']['base_hex'],c['id']
    elif op=='rfc9421.archived.verify':
        base=signature_base(message,req)
        sig=base64.b64decode(message[1]['signature'].split('=:',1)[1][:-1],validate=True)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(i['public_key_hex'])).verify(sig,base)
    if op in ['rfc9421.archived.verify','sage.content-digest']:
        expected='sha-256=:'+base64.b64encode(hashlib.sha256(message[2]).digest()).decode()+':'
        assert message[1]['content-digest']==expected,c['id']
    count+=1
print(count,'positive HTTP fixtures independently reconstructed from serialized bytes')
