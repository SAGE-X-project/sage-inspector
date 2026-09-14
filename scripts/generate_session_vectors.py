"""Generate public session known answers without importing either SAGE core."""
import copy
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
ROOT=Path(__file__).resolve().parents[1]
SOURCE=[dict(id="sage-session",kind="spec-derived",uri="sage-spec/spec/05-session.md",reference="SESSION-01..06; HPKE-05 responder confirmation. Public fixed inputs, independent Python cryptography calculation.")]
HPKE=json.loads((ROOT/'vectors/0.10.0/hpke-schedule.json').read_text())['cases'][0]
BASE=HPKE['expected']['output']
SEED=bytes.fromhex(BASE['seed_hex']); TH=bytes.fromhex(BASE['th_hex'])
T=json.loads(bytes.fromhex(BASE['transcript_hex']))
PINNED={}
for field in ('initKid','respKid'):
    private=ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('public session '+field).encode()).digest())
    PINNED[T[field]]=dict(algorithm='ed25519',public_hex=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),status='active')
PINNED[T['kemKid']]=dict(algorithm='x25519',public_hex=x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(HPKE['input']['recipient_private_hex'])).public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),status='active')
def sha(x): return hashlib.sha256(x).hexdigest()
def blob(x): return dict(hex=x.hex())
def repeat(n): return dict(byte=97,length=n)
def expand_blob(x): return bytes.fromhex(x['hex']) if 'hex' in x else bytes([x['byte']])*x['length']
def record(direction,seq,plain=b'public session record',caller=b'{}',nonce=None):
    key=HKDFExpand(algorithm=hashes.SHA256(),length=32,info=('sage-'+direction+'-key|0.10.0').encode()+TH+(seq//256).to_bytes(8,'big')).derive(SEED)
    nonce=nonce if nonce is not None else bytes(4)+seq.to_bytes(8,'big')
    aad=b'sage-record|0.10.0'+TH+bytes([direction=='s2c'])+seq.to_bytes(8,'big')+len(caller).to_bytes(4,'big')+caller
    wire=seq.to_bytes(8,'big')+nonce+ChaCha20Poly1305(key).encrypt(nonce,plain,aad)
    return key,aad,wire

def generate(out):
    out.mkdir(parents=True,exist_ok=True); cases=[]
    def case(ident,op,inp,output=None,rules=('SESSION-03',)):
        cases.append(dict(id=ident,operation=op,rule_ids=list(rules),source_ids=['sage-session'],derivation='Independent HKDF-Expand and ChaCha20-Poly1305; each case starts a fresh subject. See session-inspection.md for projections and controls.',input=inp,expected=dict(verdict='ACCEPT' if output is not None else 'REJECT',output=output or {})))
    def common(d): return dict(seed_hex=SEED.hex(),th_hex=TH.hex(),sid=BASE['sid'],direction=d)
    for d in ('c2s','s2c'):
        for seq in (0,1,255,256,511,512,767,768,999):
            key,aad,wire=record(d,seq)
            case(f'{d}-key-{seq}','sage.session.key',dict(**common(d),seq=seq),dict(key_hex=key.hex(),generation=seq//256),('SESSION-02',))
            case(f'{d}-open-{seq}','sage.session.record.open',dict(**common(d),record_hex=wire.hex(),caller_aad_hex=b'{}'.hex()),dict(plaintext_hex=b'public session record'.hex()))
    for n in (0,4033,4034):
        key,aad,wire=record('c2s',0,caller=b'a'*n)
        case(f'aad-open-{n}','sage.session.record.open',dict(**common('c2s'),record_hex=wire.hex(),caller_aad_hex=(b'a'*n).hex()),dict(plaintext_hex=b'public session record'.hex()) if n<=4033 else None)
    for n in (4033,4034):
        wire=record('c2s',0,plain=b'a',caller=b'a'*n)[2]
        case(f'aad-seal-{n}','sage.session.record.seal',dict(**common('c2s'),plaintext=repeat(1),caller_aad_hex=(b'a'*n).hex()),dict(record_sha256=sha(wire),record_bytes=len(wire)) if n<=4033 else None)
    for n in (0,1,8*1024*1024-36,8*1024*1024-35):
        wire=record('c2s',0,plain=b'a'*n,caller=b'')[2]
        case(f'plaintext-size-{n}','sage.session.record.seal',dict(**common('c2s'),plaintext=repeat(n),caller_aad_hex=''),dict(record_sha256=sha(wire),record_bytes=len(wire)) if n<=8*1024*1024-36 else None)
    valid=record('c2s',0)[2]
    for name,w in [('short',valid[:35]),('tag',valid[:-1]+bytes([valid[-1]^1])),('seq',bytes(7)+b'\x01'+valid[8:]),('nonce',valid[:8]+b'\x01'+valid[9:]),('nonce-valid-tag',record('c2s',0,nonce=b'\x01'+bytes(11))[2]),('seq-1000',record('c2s',1000)[2]),('seq-max',record('c2s',2**64-1)[2])]:
        case(name,'sage.session.record.open',dict(**common('c2s'),record_hex=w.hex(),caller_aad_hex=b'{}'.hex()),rules=('SESSION-02','SESSION-03'))
    for name,change in [('reflection',dict(direction='s2c')),('transcript',dict(th_hex='00'*32)),('aad-changed',dict(caller_aad_hex='7b207d'))]:
        inp=dict(**common('c2s'),record_hex=valid.hex(),caller_aad_hex=b'{}'.hex());inp.update(change)
        case(name,'sage.session.record.open',inp)
    (out/'session-records.json').write_text(json.dumps(dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',id='sage-session-records-0.10.0',sources=SOURCE,cases=cases),indent=2)+'\n')
    scenarios=[]
    def scenario(name,actions,provisional=False,role='responder'):
        state='RESPONSE_SENT' if provisional else 'ESTABLISHED';seen=set();send=0;now=0;last=0
        effects=dict(accepted=0,emitted=0,allocated=0,dispatch=0,confirmations=0,closed=0)
        steps=[]
        def add(op,inp,verdict='ACCEPT',output=None):
            steps.append(dict(id=f'step-{len(steps)}',operation=op,input=inp,timeout_ms=5000,expected=dict(verdict=verdict,output=output or {}),effects=copy.deepcopy(effects)))
        add('control.session.create',dict(seed_hex=SEED.hex(),th_hex=TH.hex(),tuple=T,pinned_keys=PINNED,sid=BASE['sid'],local_role=role,state=state,created_monotonic=0,idle_monotonic=0,deadline_monotonic=300,policy=dict(absolute_seconds=3600,idle_seconds=600,max_records_per_direction=1000,rekey_interval=256,close_on_invalid=False)),output=dict(state=state))
        def close():
            nonlocal state
            if state!='CLOSED': effects['closed']+=1
            state='CLOSED'
        for action in actions:
            x=copy.deepcopy(action);op=x.pop('op','receive');result={};verdict='ACCEPT'
            if op=='clock':
                now=x['monotonic'];add('control.clock.set',x);continue
            if op in ('close','restart'): close()
            elif op=='registry':
                if x['change']!='unrelated': close()
            else:
                if 'commit_monotonic' in x: now=x['commit_monotonic']
                if now>=3600 or now-last>=600 or (state=='RESPONSE_SENT' and now>=300): close()
                if state=='CLOSED': verdict='REJECT'
                elif op in ('send','parallel-send'):
                    count=x.get('count',1)
                    if state=='RESPONSE_SENT': verdict='REJECT'
                    elif send+count>1000: close();verdict='REJECT'
                    else:
                        result=dict(sequences=list(range(send,send+count)))
                        send+=count;effects['allocated']+=count
                        if not x.get('transport_failure',False): effects['emitted']+=count;last=now
                elif op=='retransmit':
                    if x.get('changed_plaintext',False): verdict='REJECT'
                    else: result=dict(identical_ciphertext=True);effects['emitted']+=1;last=now
                elif op in ('receive','parallel-receive'):
                    seq=x.get('seq',0);invalid=x.get('invalid')
                    # Real fixtures supply wire bytes, with corrupted crypto for tag failures.
                    direction='c2s' if role=='responder' else 's2c'
                    wire=record(direction,seq)[2]
                    if invalid=='tag': wire=wire[:-1]+bytes([wire[-1]^1])
                    x.update(record_hex=wire.hex(),caller_aad_hex=b'{}'.hex(),sender_role='initiator' if role=='responder' else 'responder')
                    envelope=dict(version=T['v'],context_id=T['ctx'],session_id=BASE['sid'],did=T['initDid' if role=='responder' else 'respDid'],recipient=T['respDid' if role=='responder' else 'initDid'],kid=T['initKid' if role=='responder' else 'respKid'])
                    mutations={'did':'did:sage:web:attacker.example:other','recipient':'did:sage:web:attacker.example:other','kid-active-alternative':envelope['kid']+'-alternative','context_id':'22222222-2222-4222-8222-222222222222','session_id':'AAAAAAAAAAAAAAAAAAAAAA','version':'0.9.0'}
                    if invalid in mutations: envelope['kid' if invalid=='kid-active-alternative' else invalid]=mutations[invalid]
                    if invalid=='sender-role': x['sender_role']='responder' if role=='responder' else 'initiator'
                    x['envelope_projection']=envelope
                    x['signature_verified']=invalid!='signature'
                    if seq>=1000 or seq in seen or invalid: verdict='REJECT'
                    else:
                        seen.add(seq);effects['accepted']+=1;last=now
                        if state=='RESPONSE_SENT': state='ESTABLISHED';effects['confirmations']+=1
                        if not x.get('application_reject',False): effects['dispatch']+=1
                        result=dict(accepted=1,rejected=x.get('copies',1)-1,verdicts=['ACCEPT']+['REJECT']*(x.get('copies',1)-1))
            if op.startswith('parallel-'): x['barrier']='before-atomic-commit'
            add('subject.parallel' if op.startswith('parallel-') else 'subject.call',dict(action=op,**x),verdict,result)
            add('subject.call',dict(action='inspect'),output=dict(state=state,next_send=send,received=sorted(seen),last_activity=last,keys_available=state!='CLOSED'))
        scenarios.append(dict(schema_version=2,protocol_version='0.10.0',profile='stateful-scenario',id='session-'+name,sources=SOURCE,steps=steps))
    scenario('reorder-replay',[dict(seq=999),dict(seq=0),dict(seq=256),dict(seq=0),dict(seq=1000)])
    scenario('invalid-does-not-reserve',[dict(seq=999,invalid='tag'),dict(seq=999),dict(seq=0)])
    scenario('concurrent-duplicate',[dict(op='parallel-receive',seq=256,copies=16),dict(seq=256)])
    scenario('concurrent-send',[dict(op='parallel-send',count=16),dict(op='send')])
    scenario('transport-gap',[dict(op='send',transport_failure=True),dict(op='send'),dict(op='retransmit',seq=0),dict(op='retransmit',seq=0,changed_plaintext=True)])
    scenario('send-cap',[dict(op='parallel-send',count=1000),dict(op='send')])
    scenario('direction-independent',[dict(seq=999),dict(op='send')])
    scenario('responder-direction',[dict(seq=0)],role='initiator')
    scenario('idle-boundary',[dict(op='clock',monotonic=599),dict(seq=0),dict(op='clock',monotonic=1199),dict(seq=1)])
    scenario('invalid-idle',[dict(op='clock',monotonic=599),dict(seq=0,invalid='tag'),dict(op='clock',monotonic=600),dict(seq=0)])
    keepalive=[]
    for n in range(1,7): keepalive += [dict(op='clock',monotonic=n*500),dict(seq=n)]
    scenario('absolute-boundary',keepalive+[dict(op='clock',monotonic=3599),dict(seq=7),dict(op='clock',monotonic=3600),dict(seq=8)])
    for op in ('close','restart'): scenario(op,[dict(seq=0),dict(op=op),dict(seq=1),dict(op='send')])
    for change in ('revoked-init-key','revoked-resp-key','revoked-kem-key','expired','unavailable','changed-bytes','changed-algorithm','unrelated'):
        scenario('registry-'+change,[dict(op='registry',change=change),dict(seq=0)])
    for invalid in ('did','recipient','kid-active-alternative','context_id','session_id','version','sender-role','signature','tag'):
        scenario('pinned-'+invalid,[dict(seq=0,invalid=invalid),dict(seq=0)])
    scenario('provisional-confirm',[dict(op='send'),dict(seq=7),dict(op='send')],True)
    scenario('provisional-application-reject',[dict(seq=7,application_reject=True),dict(seq=7)],True)
    scenario('provisional-invalid-retry',[dict(seq=7,invalid='tag'),dict(seq=7)],True)
    scenario('provisional-race',[dict(op='parallel-receive',seq=7,copies=16)],True)
    scenario('provisional-commit-deadline',[dict(op='clock',monotonic=299),dict(seq=7,commit_monotonic=300)],True)
    scenario('provisional-deadline',[dict(op='clock',monotonic=300),dict(seq=7)],True)
    scenario('provisional-no-clock-reset',[dict(op='clock',monotonic=299),dict(seq=7)]+keepalive+[dict(op='clock',monotonic=3599),dict(seq=8),dict(op='clock',monotonic=3600),dict(seq=9)],True)
    folder=out/'session-scenarios';folder.mkdir(exist_ok=True)
    for s in scenarios: (folder/(s['id']+'.json')).write_text(json.dumps(s,indent=2)+'\n')
    manifest=dict(schema_version=1,protocol_version='0.10.0',records_sha256=sha((out/'session-records.json').read_bytes()),scenarios=[])
    for item in scenarios:
        ident=item['id'];rules=['SESSION-06']
        if any(t in ident for t in ('reorder','invalid-does','concurrent-duplicate')): rules=['SESSION-05']
        if any(t in ident for t in ('concurrent-send','transport-gap')): rules=['SESSION-04']
        if any(t in ident for t in ('send-cap','direction','idle','absolute')): rules=['SESSION-02']
        if any(t in ident for t in ('pinned','registry')): rules=['SESSION-01','SESSION-06']
        if 'provisional' in ident: rules=['HPKE-05','SESSION-01','SESSION-02','SESSION-05']
        manifest['scenarios'].append(dict(id=ident,file=ident+'.json',sha256=sha((folder/(ident+'.json')).read_bytes()),rule_ids=rules))
    (out/'session-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(f'{len(cases)} record cases, {len(scenarios)} scenarios, {sum(len(s["steps"]) for s in scenarios)} steps')
if __name__=='__main__': generate(Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'vectors/0.10.0')
