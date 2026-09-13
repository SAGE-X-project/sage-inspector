"""Fixed HTTP/envelope boundary fixtures; no subject code or clock is used.
All keys/nonces are public test data, not production randomness.
"""
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUBLIC = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
ALICE = "did:sage:web:agent.example:alice"
BOB = "did:sage:web:agent.example:bob"
URL = "https://agent.example/call?x=1"
NOW = 1700000001
REQ = ['"@method"', '"@target-uri"', '"@authority"', '"content-type"', '"content-digest"', '"x-sage-did"', '"x-sage-version"']
RES = ['"@status"'] + [x + ';req' for x in ['"@method"', '"@target-uri"', '"@authority"', '"content-digest"', '"signature"', '"x-sage-version"']] + REQ[3:]

def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')

def jcs(o):
    # Fixture subset: ASCII keys/strings, integer timestamps, booleans; no floats.
    return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def sign_envelope(o, response=False):
    o = copy.deepcopy(o)
    o.pop('signature', None)
    prefix = b'sage-wire-response|0.10.0\n' if response else b'sage-wire-request|0.10.0\n'
    o['signature'] = b64(KEY.sign(prefix + jcs(o)))
    return o

def envelope(response=False, request=None):
    o = dict(version='0.10.0', id='11111111-1111-4111-8111-111111111111', did=ALICE,
             recipient=BOB, kid=ALICE+'#signing-1', created=1700000000, expires=1700000300,
             nonce=b64(bytes(16)), encoding='plain', payload=b64(b'{}'))
    if response:
        o.pop('payload')
        o.update(id='22222222-2222-4222-8222-222222222222', did=BOB, recipient=ALICE,
                 kid=BOB+'#signing-1', nonce=b64(bytes([1])*16), message_id=request['id'],
                 request_hash=b64(hashlib.sha256(jcs(request)).digest()), success=True, data='')
        for k in ('context_id', 'task_id'):
            if k in request:
                o[k] = request[k]
    return sign_envelope(o, response)

def http(o, request=None, overrides=None, params=None, body=None):
    response = request is not None
    content = jcs(o) if body is None else body
    h = {'Host': 'agent.example', 'Content-Type': 'application/json',
         'Content-Digest': 'sha-256=:'+base64.b64encode(hashlib.sha256(content).digest()).decode()+':',
         'X-Sage-Did': o['did'], 'X-Sage-Version': o['version'], 'Content-Length': str(len(content))}
    h.update(overrides or {})
    ps = [('keyid', '"'+o['kid']+'"'), ('alg', '"ed25519"'), ('created', str(o['created'])),
          ('expires', str(o['expires'])), ('nonce', '"'+o['nonce']+'"'), ('tag', '"sage-0.10.0"')]
    if params is not None:
        ps = params(ps)
    comp = RES if response else REQ
    member = '('+' '.join(comp)+');'+';'.join(k+'='+v for k,v in ps)
    vals = {'"@method"': 'POST', '"@target-uri"': URL, '"@authority"': 'agent.example', '"@status"': '200'}
    vals.update({'"'+k.lower()+'"':v for k,v in h.items()})
    if response:
        rv = {'"@method"': 'POST', '"@target-uri"': URL, '"@authority"': 'agent.example'}
        rv.update({'"'+k.lower()+'"':v for k,v in request[0].items()})
        vals.update({k+';req':v for k,v in rv.items()})
    base = ('\n'.join(c+': '+vals[c] for c in comp)+'\n"@signature-params": '+member).encode()
    h['Signature-Input'] = 'sig1='+member
    h['Signature'] = 'sig1=:'+base64.b64encode(KEY.sign(base)).decode()+':'
    start = 'HTTP/1.1 200 OK' if response else 'POST '+URL+' HTTP/1.1'
    raw = (start+'\r\n'+''.join(k+': '+v+'\r\n' for k,v in h.items())+'\r\n').encode()+content
    return h, raw

cases = []
proofs = {}
request = envelope()
response = envelope(True, request)
rq = http(request)
rp = http(response, rq)

def add(name, raw=None, res=b'', reason=None, now=NOW, clock=True, rule='MSG-04', **extra):
    raw = rq[1] if raw is None else raw
    inp = dict(request_hex=raw.hex(), response_hex=res.hex(), public_key_hex=PUBLIC, body_repeat=1,
               now_unix=now, clock_trusted=clock, expected_target=URL, expected_recipient=BOB,
               trusted_keys={ALICE+'#signing-1':PUBLIC, BOB+'#signing-1':PUBLIC})
    inp.update(extra)
    for field in ['request', 'response']:
        padding=extra.get(field+'_padding', 0)
        if padding:
            content=bytes.fromhex(inp[field+'_hex'])
            if content[-padding:] != b' '*padding:
                raise ValueError('invalid body padding recipe')
            inp[field+'_hex']=(content[:-padding]+b' ').hex()
    cases.append(dict(id=name, operation='sage.http.verify', rule_ids=[rule],
                      source_ids=['sage-http', 'sage-transport', 'rfc9421'],
                      derivation='Public fixed key; independently signed inner and outer messages. '+(reason or 'Positive cryptographic boundary control.'),
                      input=inp, expected=dict(verdict='REJECT' if reason else 'ACCEPT', output={} if reason else {'valid':True})))
    proofs[name] = dict(reason=reason, request_sha256=hashlib.sha256(raw).hexdigest(), response_sha256=hashlib.sha256(res).hexdigest())

add('valid-request')
add('valid-response', res=rp[1], rule='TRANSPORT-03')
add('valid-reordered-parameters', http(request, params=lambda ps:list(reversed(ps)))[1], rule='MSG-01')
add('valid-whitespace-body', http(request, body=json.dumps(request, indent=2).encode())[1])
pretty = http(request, body=json.dumps(request, indent=2).encode())
add('valid-response-canonical-request-hash', pretty[1], http(response, pretty)[1], rule='TRANSPORT-03')
for label, now, reason in [('created-minus-30',1699999970,None), ('created-minus-31',1699999969,'freshness'),
                           ('expiry-plus-29',1700000329,None), ('expiry-plus-30',1700000330,'freshness')]:
    add(label, now=now, reason=reason, rule='MSG-05')
add('untrusted-clock', clock=False, reason='clock', rule='MSG-05')
for label, created, expires, reason in [('lifetime-one',NOW,NOW+1,None),('lifetime-zero',NOW,NOW,'lifetime'),
                                       ('lifetime-301',NOW,NOW+301,'lifetime'),('negative-created',-1,10,'timestamp'),
                                       ('fractional-created',1700000000.5,1700000300,'timestamp')]:
    o=sign_envelope(dict(request, created=created, expires=expires))
    add(label,http(o)[1],reason=reason,rule='MSG-05')
for name in ['Signature','Signature-Input','Content-Digest','Content-Type','X-Sage-Did','X-Sage-Version']:
    h = (name+': '+rq[0][name]+'\r\n').encode()
    add('duplicate-'+name.lower(),rq[1].replace(h,h+h),reason='duplicate')
for label, old, new, why in [('conflicting-length',b'Content-Length: ',b'Content-Length: 1\r\nContent-Length: ','framing'),
                            ('transfer-and-length',b'Content-Length: ',b'Transfer-Encoding: chunked\r\nContent-Length: ','framing'),
                            ('ambiguous-authority',b'Host: agent.example',b'Host: attacker.example','authority')]:
    add(label,rq[1].replace(old,new),reason=why)
add('truncated-body',rq[1][:-1],reason='framing')
add('trailing-body',rq[1]+b'x',reason='framing')
for field,value in [('Content-Encoding','gzip'),('Trailer','X-Foo'),('Content-Type','multipart/mixed'),
                    ('X-Sage-Message-ID','33333333-3333-4333-8333-333333333333'),('X-Sage-Context-ID','33333333-3333-4333-8333-333333333333'),
                    ('X-Sage-Version','0.9.0'),('X-Sage-Did',BOB)]:
    reason='projection' if field.startswith('X-Sage') else 'profile'
    add('header-'+field.lower(),http(request,overrides={field:value})[1],reason=reason,rule='TRANSPORT-05')
for label, transform in [('wrong-tag',lambda p:[(k,'"other"' if k=='tag' else v) for k,v in p]),
                          ('missing-tag',lambda p:[(k,v) for k,v in p if k!='tag']),
                          ('duplicate-tag',lambda p:p+[p[-1]]),('unknown-param',lambda p:p+[('other','1')]),
                          ('nonce-body-mismatch',lambda p:[(k,'"AQEBAQEBAQEBAQEBAQEBAQ"' if k=='nonce' else v) for k,v in p])]:
    add(label,http(request,params=transform)[1],reason='parameters' if 'nonce' not in label else 'projection',rule='MSG-01')
# Size measurements explicitly count serialized field lines including CRLF.
for n in [32768,32769]:
    head,body=rq[1].split(b'\r\n\r\n',1)
    fields=head.split(b'\r\n',1)[1]+b'\r\n'
    padding=b'X-Padding: '+b'x'*(n-len(fields)-len(b'X-Padding: \r\n'))+b'\r\n'
    raw=head+b'\r\n'+padding+b'\r\n'+body
    add('fields-'+str(n),raw,reason='fields-size' if n>32768 else None)
# OWS is not signature input; a valid canonical signature can have long outer OWS.
for field in ['Signature','Signature-Input']:
    for n in [8192,8193]:
        old=(field+': '+rq[0][field]+'\r\n').encode()
        new=(field+': '+rq[0][field]).encode()+b' '*(n-len(rq[0][field]))+b'\r\n'
        add(field.lower()+'-value-'+str(n),rq[1].replace(old,new),reason='signature-size' if n>8192 else None)
for name, change, reason in [('wrong-request-hash',{'request_hash':b64(bytes(32))},'request-hash'),
                             ('wrong-message-id',{'message_id':'33333333-3333-4333-8333-333333333333'},'response-binding'),
                             ('wrong-recipient',{'recipient':BOB},'response-binding'),
                             ('context-injected',{'context_id':'33333333-3333-4333-8333-333333333333'},'response-binding'),
                             ('task-injected',{'task_id':'33333333-3333-4333-8333-333333333333'},'response-binding'),
                             ('error-on-success',{'error':'operation_failed'},'schema')]:
    o=sign_envelope(dict(response,**change),True)
    add(name,res=http(o,rq)[1],reason=reason,rule='TRANSPORT-03')
unsigned=dict(request);unsigned.pop('signature')
payload_hash=b64(hashlib.sha256(base64.urlsafe_b64decode(request['payload']+'==')).digest())
for label,value in [('hash-without-signature',b64(hashlib.sha256(jcs(unsigned)).digest())),('payload-only-hash',payload_hash),
                    ('hash-raw-pretty-request',b64(hashlib.sha256(json.dumps(request,indent=2).encode()).digest()))]:
    o=sign_envelope(dict(response,request_hash=value),True)
    add(label,res=http(o,rq)[1],reason='request-hash',rule='TRANSPORT-03')
changed=sign_envelope(dict(request,metadata={'note':'changed'}))
changed_http=http(changed)
# Outer response is correctly rebound to the changed request; inner hash is stale.
add('stale-hash-with-valid-outer-binding',changed_http[1],http(response,changed_http)[1],reason='request-hash',rule='TRANSPORT-03')
add('missing-stored-request',b'',rp[1],reason='request-context',rule='TRANSPORT-03')
o=sign_envelope(dict(response,success=False,error='operation_failed'),True)
add('valid-signed-application-error',res=http(o,rq)[1],rule='TRANSPORT-03')
for label, changed in [('request-inner-signature',dict(request,signature=b64(bytes(64)))),('request-payload-tamper',dict(request,payload=b64(b'changed')))]:
    add(label,http(changed)[1],reason='inner-signature',rule='TRANSPORT-02')
o=dict(response,signature=b64(bytes(64)))
add('response-inner-signature',res=http(o,rq)[1],reason='inner-signature',rule='TRANSPORT-03')
add('unsigned-response',res=rp[1].replace(('Signature: '+rp[0]['Signature']+'\r\n').encode(),b''),reason='signature-fields')
# Additional envelope schema mutations retain valid inner and outer signatures.
for name,change in [('unknown-member',{'unknown':True}),('padded-payload',{'payload':request['payload']+'='}),('null-context',{'context_id':None})]:
    o=sign_envelope(dict(request,**change))
    add(name,http(o)[1],reason='schema',rule='TRANSPORT-01')

for n in [16777216,16777217]:
    padding=n-len(jcs(request))
    raw=http(request,body=jcs(request)+b' '*padding)
    add('request-body-'+str(n),raw[1],reason='body-size' if n>16777216 else None,request_padding=padding)
    padding=n-len(jcs(response))
    raw=http(response,rq,body=jcs(response)+b' '*padding)
    add('response-body-'+str(n),res=raw[1],reason='body-size' if n>16777216 else None,response_padding=padding)
for now in [1700000129,1700000130]:
    o=sign_envelope(dict(response,expires=1700000100),True)
    add('response-expiry-'+str(now),res=http(o,rq)[1],now=now,reason='freshness' if now==1700000130 else None,rule='MSG-05')

sources=[dict(id='sage-http',kind='spec-derived',uri='sage-spec/spec/03-rfc9421.md',reference='MSG-01..05; cryptographic HTTP boundary, fresh isolated replay state.'),
         dict(id='sage-transport',kind='spec-derived',uri='sage-spec/spec/08-transport.md',reference='TRANSPORT-01..05; inner signature domains and complete signed request hash.'),
         dict(id='rfc9421',kind='spec-derived',uri='https://www.rfc-editor.org/rfc/rfc9421.html',reference='Ordered signature bases and request-bound responses.')]
suite=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',id='sage-http-boundaries-0.10.0',sources=sources,cases=cases)
root=Path(__file__).resolve().parents[1]
out=Path(sys.argv[1]) if len(sys.argv)>1 else root/'vectors/0.10.0/http-boundaries.json'
out.write_text(json.dumps(suite,indent=2)+'\n')
if len(sys.argv)>2:
    Path(sys.argv[2]).write_text(json.dumps(proofs,indent=2)+'\n')
print(len(cases),'boundary cases',out)
