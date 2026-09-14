"""Public test-only HPKE vectors. No SAGE code/dependencies are imported.
RFC 9180 A.2.1 anchors the KEM/export schedule; RFC 5869 anchors HKDF.
"""
import base64
import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

ROOT = Path(__file__).resolve().parents[1]
SKR = bytes.fromhex('8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb')
SKE = bytes.fromhex('f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600')
SIGN = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))
PUB = SIGN.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
KEM = b'KEM\x00\x20'
SUITE = b'HPKE\x00\x20\x00\x01\x00\x03'


def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def canonical(o):
    return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha(b):
    return hashlib.sha256(b).digest()


def extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def expand(prk, info, length=32):
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def le(suite, salt, label, value):
    return extract(salt, b'HPKE-v1'+suite+label+value)


def lx(suite, prk, label, info, length=32):
    return expand(prk, length.to_bytes(2,'big')+b'HPKE-v1'+suite+label+info, length)


def public(private):
    return x25519.X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)


def dh(private, peer):
    # OpenSSL rejects null shared results; never turn them into a normal key.
    return x25519.X25519PrivateKey.from_private_bytes(private).exchange(x25519.X25519PublicKey.from_public_bytes(peer))


def exporter(sk, enc, info, context):
    shared = lx(KEM, le(KEM,b'',b'eae_prk',dh(sk,enc)), b'shared_secret',enc+public(sk))
    ks_context = b'\0'+le(SUITE,b'',b'psk_id_hash',b'')+le(SUITE,b'',b'info_hash',info)
    secret = le(SUITE,shared,b'secret',b'')
    exported_secret = lx(SUITE,secret,b'exp',ks_context)
    value = lx(SUITE,exported_secret,b'sec',context)
    return dict(kem_shared_secret_hex=shared.hex(),key_schedule_context_hex=ks_context.hex(),
                hpke_secret_hex=secret.hex(),exporter_secret_hex=exported_secret.hex(),exporter_hex=value.hex())


# Published known answers, not generated expectations.
RFC_INFO=bytes.fromhex('4f6465206f6e2061204772656369616e2055726e')
RFC_EXPORTS={'':'4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e',
             '00':'8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69',
             '54657374436f6e74657874':'5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53'}
for context, expected in RFC_EXPORTS.items():
    actual=exporter(SKR,public(SKE),RFC_INFO,bytes.fromhex(context))
    assert actual['exporter_hex']==expected
    assert actual['kem_shared_secret_hex']=='0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7'
    assert actual['exporter_secret_hex']=='a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922'
assert expand(bytes.fromhex('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'),bytes.fromhex('f0f1f2f3f4f5f6f7f8f9'),42).hex()=='3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'

B=dict(v='0.10.0',ctx='11111111-1111-4111-8111-111111111111',initDid='did:sage:web:agent.example:alice',
       respDid='did:sage:web:agent.example:bob',initKid='did:sage:web:agent.example:alice#signing-1',
       respKid='did:sage:web:agent.example:bob#signing-1',kemKid='did:sage:web:agent.example:bob#kem-1',
       suite='hpke-base+x25519+hkdf-sha256',combiner='e2e-x25519-hkdf-v1',nonce=b64(bytes(16)))


def finish(exported, shared, transcript):
    th=sha(canonical(transcript))
    prk=extract(th,exported+shared)
    seed=expand(prk,b'sage-hpke-combiner|0.10.0'+th)
    ack_key=expand(seed,b'sage-hpke-ack|0.10.0'+th)
    ack=hmac.new(ack_key,th,hashlib.sha256).digest()
    return dict(transcript_hex=canonical(transcript).hex(),th_hex=th.hex(),ss_e2e_hex=shared.hex(),prk_hex=prk.hex(),
                seed_hex=seed.hex(),ack_key_hex=ack_key.hex(),ack_tag_hex=ack.hex(),sid=b64(sha(b'sage-session|0.10.0'+th)[:16]))


def signed_completion(t, ack):
    p=dict(v='0.10.0',task='hpke/complete@0.10.0',transcript=t,ackTagB64=b64(ack))
    p['sigB64']=b64(SIGN.sign(b'sage-hpke-complete|0.10.0\n'+canonical(p)))
    return p


def derive(binding, c, s, kid):
    info=b'sage-hpke-info|0.10.0\n'+canonical(binding)
    ec=b'sage-hpke-export|0.10.0\n'+sha(info)
    enc=public(SKE)
    values=exporter(SKR,enc,info,ec)
    init=dict(binding,task='hpke/init@0.10.0',enc=b64(enc),ephC=b64(public(c)))
    t=dict(init,ephS=b64(public(s)),kid=kid)
    shared=dh(c,public(s))
    assert shared==dh(s,public(c))
    assert len({public(SKE), public(c), public(s), public(SKR)})==4
    values.update(finish(bytes.fromhex(values['exporter_hex']),shared,t))
    completion=signed_completion(t,bytes.fromhex(values['ack_tag_hex']))
    values.update(binding_hex=canonical(binding).hex(),info_hex=info.hex(),export_context_hex=ec.hex(),
                  enc_hex=enc.hex(),ephemeral_c_hex=public(c).hex(),ephemeral_s_hex=public(s).hex(),
                  initiation_hex=canonical(init).hex(),completion_hex=canonical(completion).hex())
    return values


sources=[dict(id='rfc9180',kind='published',uri='https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.2.1',reference='Base mode 0, suite 0020/0001/0003; Appendix A.2.1 known answers. KEM suite prefix corrected by verified erratum 7937.'),
         dict(id='rfc5869',kind='published',uri='https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1',reference='SHA-256 extract and expand meanings; Appendix A.1 known-answer check.'),
         dict(id='sage-hpke',kind='spec-derived',uri='sage-spec/spec/04-hpke.md',reference='Pinned HPKE-01..06; B/info/exportCtx/T/th/combiner/ACK/closed completion, test-only entropy controls.'),
         dict(id='sage-session',kind='spec-derived',uri='sage-spec/spec/05-session.md',reference='SESSION-01 transcript-derived public session id.')]
primitive=[]
full=[]
proofs={}


def add(group, ident, op, inp, output=None, reject=False, reason=None, rule='HPKE-03'):
    group.append(dict(id=ident,operation=op,rule_ids=[rule],source_ids=[x['id'] for x in sources],
                      derivation='Public fixed material independently calculated using Python HKDF/X25519 and checked against RFC anchors; no SAGE imports.'+((' Rejection: '+reason) if reason else ''),
                      input=inp,expected=dict(verdict='REJECT' if reject else 'ACCEPT',output={} if reject else output)))
    if reason:
        proofs[ident]=reason


for n,(context,value) in enumerate(RFC_EXPORTS.items()):
    add(primitive,'rfc9180-export-'+str(n),'rfc9180.export',dict(private_key_hex=SKR.hex(),enc_hex=public(SKE).hex(),info_hex=RFC_INFO.hex(),export_context_hex=context),{'exporter_hex':value},rule='HPKE-01')

schedules=[]
for n in range(3):
    binding=copy.deepcopy(B)
    if n==1:
        binding['ctx']='22222222-2222-4222-8222-222222222222'
        binding['nonce']=b64(bytes([1])*16)
    if n==2:
        binding.update(initDid=B['respDid'],respDid=B['initDid'],initKid=B['respKid'],respKid=B['initKid'],kemKid=B['initDid']+'#kem-1')
    c=sha(('public SAGE C '+str(n)).encode());s=sha(('public SAGE S '+str(n)).encode())
    kid='33333333-3333-4333-8333-33333333333'+str(n)
    values=derive(binding,c,s,kid)
    inp=dict(binding=binding,recipient_private_hex=SKR.hex(),hpke_ephemeral_private_hex=SKE.hex(),
             client_ephemeral_private_hex=c.hex(),server_ephemeral_private_hex=s.hex(),kid=kid)
    add(full,'schedule-'+str(n),'sage.hpke.derive',inp,values)
    schedules.append((inp,values))
    add(primitive,'sage-export-'+str(n),'rfc9180.export',dict(private_key_hex=SKR.hex(),enc_hex=values['enc_hex'],info_hex=values['info_hex'],export_context_hex=values['export_context_hex']),{'exporter_hex':values['exporter_hex']},rule='HPKE-02')
    add(primitive,'combiner-'+str(n),'sage.hpke.combine',dict(exporter_hex=values['exporter_hex'],ss_e2e_hex=values['ss_e2e_hex'],th_hex=values['th_hex']),{'seed_hex':values['seed_hex']})
    for part in ['binding','transcript']:
        add(primitive,part+'-jcs-'+str(n),'jcs.canonicalize',{'document_hex':values[part+'_hex']},{'canonical_hex':values[part+'_hex']},rule='HPKE-02' if part=='binding' else 'HPKE-03')
    p=json.loads(bytes.fromhex(values['completion_hex']));sig=base64.urlsafe_b64decode(p.pop('sigB64')+'==')
    message=b'sage-hpke-complete|0.10.0\n'+canonical(p)
    add(primitive,'completion-signature-'+str(n),'signature.verify',dict(algorithm='ed25519',public_key_hex=PUB.hex(),message_hex=message.hex(),signature_hex=sig.hex()),{'valid':True},rule='HPKE-04')

first,values=schedules[0]
for name,info,context in [('changed-info',b'changed',bytes.fromhex(values['export_context_hex'])),('changed-export-context',bytes.fromhex(values['info_hex']),b'changed')]:
    v=exporter(SKR,public(SKE),info,context)
    assert v['exporter_hex']!=values['exporter_hex']
    add(primitive,name,'rfc9180.export',dict(private_key_hex=SKR.hex(),enc_hex=values['enc_hex'],info_hex=info.hex(),export_context_hex=context.hex()),{'exporter_hex':v['exporter_hex']},rule='HPKE-02')
for label,enc in [('zero',bytes(32)),('one',b'\x01'+bytes(31)),('short',bytes(31))]:
    add(primitive,'kem-'+label,'rfc9180.export',dict(private_key_hex=SKR.hex(),enc_hex=enc.hex(),info_hex=values['info_hex'],export_context_hex=values['export_context_hex']),reject=True,reason='invalid-kem',rule='HPKE-01')
for label,private,peer in [('client',first['client_ephemeral_private_hex'],values['ephemeral_s_hex']),('server',first['server_ephemeral_private_hex'],values['ephemeral_c_hex']),('zero',first['client_ephemeral_private_hex'],bytes(32).hex()),('one',first['client_ephemeral_private_hex'],(b'\x01'+bytes(31)).hex()),('short',first['client_ephemeral_private_hex'],bytes(31).hex())]:
    bad=label in ['zero','one','short']
    add(primitive,'e2e-'+label,'x25519.exchange',dict(private_key_hex=private,public_key_hex=peer),{'shared_secret_hex':values['ss_e2e_hex']},reject=bad,reason='invalid-dh' if bad else None)
for label,ss in [('zero',bytes(32).hex()),('short',bytes(31).hex())]:
    add(primitive,'combiner-'+label,'sage.hpke.combine',dict(exporter_hex=values['exporter_hex'],ss_e2e_hex=ss,th_hex=values['th_hex']),reject=True,reason='invalid-combiner-input')

# Completion verification is a cryptographic projection over authenticated outer
# envelope/key observations; live resolver and envelope verification are separate.
pending=dict(initiation_hex=values['initiation_hex'],hpke_ephemeral_private_hex=SKE.hex(),recipient_public_hex=public(SKR).hex(),
             client_ephemeral_private_hex=first['client_ephemeral_private_hex'],responder_signing_public_hex=PUB.hex())
complete=json.loads(bytes.fromhex(values['completion_hex']))
init=json.loads(bytes.fromhex(values['initiation_hex']))

def completion_case(name,p,reason=None):
    add(full,name,'sage.hpke.complete.verify',dict(pending=pending,completion_hex=canonical(p).hex()),
        {'seed_hex':values['seed_hex'],'th_hex':values['th_hex'],'sid':values['sid']},reject=reason is not None,reason=reason,rule='HPKE-04')

completion_case('completion-valid',complete)
for field in init:
    t=copy.deepcopy(complete['transcript'])
    if field in ['enc','ephC','nonce']:
        t[field]=b64(bytes([2])*(16 if field=='nonce' else 32))
    else:
        t[field]=t[field]+'-changed'
    # Recompute ACK and signature: echo equality is still mandatory.
    f=finish(bytes.fromhex(values['exporter_hex']),bytes.fromhex(values['ss_e2e_hex']),t)
    completion_case('echo-'+field,signed_completion(t,bytes.fromhex(f['ack_tag_hex'])),'echo')
for name,modify,reason in [('wrong-ack',lambda p:p.update(ackTagB64=b64(bytes(32))),'ack'),
                           ('short-ack',lambda p:p.update(ackTagB64=b64(bytes(31))),'schema'),
                           ('padded-ack',lambda p:p.update(ackTagB64=p['ackTagB64']+'='),'schema'),
                           ('wrong-version',lambda p:p.update(v='0.9.0'),'schema'),
                           ('wrong-task',lambda p:p.update(task='hpke/complete@v1'),'schema'),
                           ('unknown-member',lambda p:p.update(extra='x'),'schema')]:
    p=copy.deepcopy(complete);modify(p);p.pop('sigB64')
    p['sigB64']=b64(SIGN.sign(b'sage-hpke-complete|0.10.0\n'+canonical(p)))
    completion_case(name,p,reason)
p=copy.deepcopy(complete);p['sigB64']=b64(bytes(64));completion_case('invalid-signature',p,'signature')
p=copy.deepcopy(complete);p['sigB64']+='=';completion_case('padded-signature',p,'schema')
p=copy.deepcopy(complete);p.pop('sigB64');completion_case('unsigned-completion',p,'schema')
p=copy.deepcopy(complete);p['transcript']['extra']='x';p=signed_completion(p['transcript'],bytes.fromhex(values['ack_tag_hex']));completion_case('unknown-transcript-member',p,'schema')
p=copy.deepcopy(complete);p['transcript']['ephS']=b64(bytes(32));p=signed_completion(p['transcript'],bytes.fromhex(values['ack_tag_hex']));completion_case('zero-ephS',p,'invalid-dh')
p=copy.deepcopy(complete);p['transcript']['kid']='not-a-uuid';p=signed_completion(p['transcript'],bytes.fromhex(values['ack_tag_hex']));completion_case('invalid-handle',p,'schema')
# Wrong pending context must not consume another handshake's completion.
other=copy.deepcopy(pending);other['initiation_hex']=schedules[1][1]['initiation_hex'];other['client_ephemeral_private_hex']=schedules[1][0]['client_ephemeral_private_hex']
add(full,'different-pending-request','sage.hpke.complete.verify',dict(pending=other,completion_hex=values['completion_hex']),reject=True,reason='echo',rule='HPKE-04')


for name,field,value in [('unknown-suite','suite','other'),('unknown-combiner','combiner','other'),('old-version','v','0.9.0'),('extra-binding','unknown','x')]:
    inp=copy.deepcopy(first);inp['binding'][field]=value
    add(full,'derive-'+name,'sage.hpke.derive',inp,reject=True,reason='binding',rule='HPKE-01')
for length in [16384,16385]:
    raw=canonical(complete)
    raw+=b' '*(length-len(raw))
    add(full,'completion-size-'+str(length),'sage.hpke.complete.verify',dict(pending=pending,completion_hex=raw.hex()),
        {'seed_hex':values['seed_hex'],'th_hex':values['th_hex'],'sid':values['sid']},reject=length>16384,reason='bounds' if length>16384 else None,rule='HPKE-06')
p=copy.deepcopy(complete);p['transcript']['ephS']=b64(bytes(31));p=signed_completion(p['transcript'],bytes.fromhex(values['ack_tag_hex']));completion_case('short-ephS',p,'schema')


def scenarios():
    result=[]
    for name,bad,utc,mono,keys in [('valid',None,1700000001,11,True),('wrong-ack','wrong-ack',1700000001,11,True),
                                 ('wrong-pending','different-pending-request',1700000001,11,True),
                                 ('monotonic-expiry',None,1700000001,310,True),('utc-expiry',None,1700000300,11,True),
                                 ('bound-key-invalid',None,1700000001,11,False)]:
        target=next((c for c in full if c['id']==bad),None)
        received=target['input']['completion_hex'] if target else values['completion_hex']
        state_pending=target['input']['pending'] if target else pending
        initial=dict(pending=state_pending,emitted_utc=1700000000,emitted_monotonic=10,initiation_expires=1700000300)
        accepted=name=='valid'
        effects={'sessions_created':int(accepted),'pending_destroyed':1}
        steps=[dict(id='pending',operation='control.hpke.pending',input=initial,timeout_ms=1000,
                    expected={'verdict':'ACCEPT','output':{'state':'INIT_SENT'}},effects={'sessions_created':0,'pending_destroyed':0}),
               dict(id='complete',operation='subject.call',input=dict(action='hpke.complete',completion_hex=received,utc=utc,monotonic=mono,bound_keys_current=keys,outer_response_authenticated=True),timeout_ms=1000,
                    expected={'verdict':'ACCEPT' if accepted else 'REJECT','output':{'state':'ESTABLISHED','sid':values['sid']} if accepted else {}},effects=effects),
               dict(id='inspect',operation='subject.call',input={'action':'hpke.inspect'},timeout_ms=1000,
                    expected={'verdict':'ACCEPT','output':{'state':'ESTABLISHED' if accepted else 'CLOSED','pending_present':False}},effects=effects)]
        if name in ['wrong-ack','wrong-pending']:
            steps.append(dict(id='retry-after-destruction',operation='subject.call',
                              input=dict(action='hpke.complete',completion_hex=received,utc=utc,monotonic=mono+1,bound_keys_current=True,outer_response_authenticated=True),
                              timeout_ms=1000,expected={'verdict':'REJECT','output':{}},effects=effects))
        result.append(dict(schema_version=2,protocol_version='0.10.0',profile='stateful-scenario',id='hpke-'+name,sources=sources,steps=steps))
    return result


def suite(name,cases):
    return dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',id=name,sources=sources,cases=cases)


def main():
    out=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'vectors/0.10.0'
    out.mkdir(parents=True,exist_ok=True)
    for name,cases in [('hpke-primitives',primitive),('hpke-schedule',full)]:
        (out/(name+'.json')).write_text(json.dumps(suite('sage-'+name+'-0.10.0',cases),indent=2)+'\n')
        print(name,len(cases))
    (out/'hpke-rejection-reasons.json').write_text(json.dumps(proofs,indent=2)+'\n')
    directory=out/'hpke-scenarios';directory.mkdir(exist_ok=True)
    for scenario in scenarios():
        (directory/(scenario['id']+'.json')).write_text(json.dumps(scenario,indent=2)+'\n')
    print('hpke-scenarios',len(scenarios()))


if __name__=='__main__':
    main()
