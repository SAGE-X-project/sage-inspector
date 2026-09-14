"""Independent public Ed25519 registry/Card fixtures; no SAGE imports."""
import base64,copy,hashlib,json,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519,x25519
from cryptography.hazmat.primitives import serialization
ROOT=Path(__file__).resolve().parents[1]
DID='did:sage:web:agents.example.com:alice';RID='web:agents.example.com';NOW=1700000000
SK=ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'public registry fixture signing key').digest())
def public(k):return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def b64(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def jcs(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def challenge(rid,agent,name,alg,key):
    values=[rid.encode(),agent.encode(),name.encode(),alg.encode(),key]
    return b'sage-pop-0.10.0'+b''.join(len(v).to_bytes(2,'big')+v for v in values)
def entry(name,alg,key,signer):
    return dict(name=name,alg=alg,key=b64(key),proof=dict(signer=DID+'#'+signer,value=b64(SK.sign(challenge(RID,'alice',name,alg,key)))),state='accepted')
KEY=entry('signing-1','ed25519',public(SK),'signing-1')
KEM=entry('kem-1','x25519',public(x25519.X25519PrivateKey.from_private_bytes(hashlib.sha256(b'public registry KEM').digest())),'signing-1')
RECORD=dict(id=DID,controller='test-controller',keys=[KEM,KEY],services=[dict(name='api',type='Agent',uri='https://agents.example.com/api')],state='active',version='1')
def signed(card):
    card=copy.deepcopy(card);card['proof'].pop('proofValue',None)
    card['proof']['proofValue']=b64(SK.sign(b'sage-card-0.10.0\0'+jcs(card)));return card
CARD=signed(dict(version='0.10.0',id=DID,recordVersion='1',name='Alice',services=RECORD['services'],capabilities=['read'],issued=NOW,expires=NOW+300,proof=dict(type='SageAgentCardSignature0_10_0',verificationMethod=DID+'#signing-1',alg='ed25519')))
SOURCE=[dict(id='registry-spec',kind='spec-derived',uri='sage-spec/spec/09-registry.md',reference='0.10.0 chapters06/07/09/10: ID, REG, CARD and RESOLVE rules. Independent public Python fixtures, Node audit, synthetic authority only.')]
def generate(out):
    out.mkdir(parents=True,exist_ok=True);cases=[]
    def case(name,op,inp,accept=True,output=None,rules=('REG-04',)):
        cases.append(dict(id=name,operation=op,rule_ids=list(rules),source_ids=['registry-spec'],derivation='Explicit independently authored boundary expectation; Ed25519 signatures from Python cryptography, no core imports. See registry-inspection.md.',input=inp,expected=dict(verdict='ACCEPT' if accept else 'REJECT',output=(output if output is not None else dict(valid=True)) if accept else {})))
    for name,did,ok in [('web',DID,True),('chain','did:sage:eip155:1:0x'+'ab'*20+':alice',True),('agent-max','did:sage:web:agents.example.com:'+'a'*64,True),('agent-over','did:sage:web:agents.example.com:'+'a'*65,False),('legacy','did:sage:ethereum:0xabc',False),('alias','did:sage:eth:0xabc',False),('reserved','did:sage:solana:mainnet:alice',False),('upper-kind',DID.replace(':web:',':WEB:'),False),('upper-domain',DID.replace('agents','Agents'),False),('port',DID.replace('.com:', '.com:443:'),False),('ip',DID.replace('agents.example.com','127.0.0.1'),False),('percent',DID+'%20',False),('query',DID+'?x=1',False),('fragment',DID+'#key',False),('empty',DID[:-5],False),('unicode',DID+'가',False),('dot',DID[:-5]+'.',False),('chain-leading-zero','did:sage:eip155:01:0x'+'ab'*20+':alice',False),('upper-address','did:sage:eip155:1:0x'+'AB'*20+':alice',False),('extra-locator',DID+':other',False)]:
        case('did-'+name,'sage.did.validate',dict(did=did,supported_kinds=['eip155','web']),ok,rules=('ID-01','ID-02'))
    for key in (KEY,KEM):
        msg=challenge(RID,'alice',key['name'],key['alg'],base64.urlsafe_b64decode(key['key']+'='))
        sig=base64.urlsafe_b64decode(key['proof']['value']+'==')
        for label,message,ok in [('valid',msg,True),('registry',challenge('web:other.example','alice',key['name'],key['alg'],base64.urlsafe_b64decode(key['key']+'=')),False),('name',challenge(RID,'alice','other',key['alg'],base64.urlsafe_b64decode(key['key']+'=')),False),('agent',challenge(RID,'bob',key['name'],key['alg'],base64.urlsafe_b64decode(key['key']+'=')),False)]:
            case(key['name']+'-signature-'+label,'signature.verify',dict(algorithm='ed25519',public_key_hex=public(SK).hex(),message_hex=message.hex(),signature_hex=sig.hex()),ok)
        if key==KEY:
            case('pop-current','sage.registry.pop.verify',dict(did=DID,name=key['name'],alg=key['alg'],public_key_hex=public(SK).hex(),signature_hex=sig.hex()))
            legacy=SK.sign(hashlib.sha256(('SAGE-PoP:'+DID+':'+public(SK).hex()).encode()).digest())
            case('pop-legacy','sage.registry.pop.verify',dict(did=DID,name=key['name'],alg=key['alg'],public_key_hex=public(SK).hex(),signature_hex=legacy.hex()),False)
    def rec(name,record,ok=True,mode='read',now=NOW):case('record-'+name,'sage.registry.record.verify',dict(record_hex=jcs(record).hex(),expected_did=DID,now=now,mode=mode),ok,rules=('REG-01','REG-02','REG-04','RESOLVE-02'))
    rec('valid',RECORD)
    for name,change in [('unknown',lambda x:x.update(extra=True)),('version-zero',lambda x:x.update(version='0')),('version-leading-zero',lambda x:x.update(version='01')),('version-overflow',lambda x:x.update(version='18446744073709551616')),('private',lambda x:x['keys'][1].update(d='secret')),('duplicate-name',lambda x:x['keys'].append(copy.deepcopy(KEY))),('duplicate-material',lambda x:x['keys'].append(dict(KEY,name='signing-2'))),('unsorted',lambda x:x['keys'].reverse()),('service-collision',lambda x:x['services'][0].update(name='signing-1')),('service-http',lambda x:x['services'][0].update(uri='http://agents.example.com')),('service-userinfo',lambda x:x['services'][0].update(uri='https://user@agents.example.com')),('service-fragment',lambda x:x['services'][0].update(uri='https://agents.example.com/#x')),('missing-proof',lambda x:x['keys'][0].pop('proof')),('wrong-endorser',lambda x:x['keys'][0]['proof'].update(signer=DID+'#missing')),('padded-key',lambda x:x['keys'][0].update(key=KEM['key']+'=')),('wrong-id',lambda x:x.update(id=DID+'x')),('key-state',lambda x:x['keys'][1].update(state='pending'))]:
        x=copy.deepcopy(RECORD);change(x);rec(name,x,False)
    for state in ('created','deactivated'):
        x=copy.deepcopy(RECORD);x['state']=state;rec(state,x)
        case('resolve-'+state,'sage.registry.resolve',dict(record=x,now=NOW),output=dict(state=state,version='1',verification_methods=[],authentication=[],assertion_method=[],key_agreement=[],services=x['services']),rules=('RESOLVE-01','RESOLVE-03'))
        case('authenticate-'+state,'sage.registry.authenticate',dict(record=x,keyid=DID+'#signing-1',sender=DID,expected_peer=DID,alg='ed25519',now=NOW),False,rules=('ID-03','RESOLVE-03'))
    sk2=ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'public registry second signer').digest())
    second=entry('signing-2','ed25519',public(sk2),'signing-2')
    second['proof']['value']=b64(sk2.sign(challenge(RID,'alice','signing-2','ed25519',public(sk2))))
    for expired in (False,True):
        x=copy.deepcopy(RECORD);x['keys'].append(second)
        if expired:x['keys'][1]['expires']=NOW
        else:x['keys'][1]['state']='revoked'
        # A read can validate historical endorsement even though the signer cannot authenticate.
        rec('historical-'+str(expired),x)
        rec('new-endorsement-'+str(expired),x,False,mode='add-kem')
        case('authenticate-historical-'+str(expired),'sage.registry.authenticate',dict(record=x,keyid=DID+'#signing-1',sender=DID,expected_peer=DID,alg='ed25519',now=NOW),False,rules=('ID-03','REG-04','RESOLVE-04'))
    for name,mut,ok in [('valid',{},True),('unknown-key',dict(keyid=DID+'#missing'),False),('other-sender',dict(sender=DID+'x'),False),('other-peer',dict(expected_peer=DID+'x'),False),('algorithm',dict(alg='ecdsa-p256-sha256'),False),('missing-fragment',dict(keyid=DID),False)]:
        inp=dict(record=RECORD,keyid=DID+'#signing-1',sender=DID,expected_peer=DID,alg='ed25519',now=NOW);inp.update(mut)
        case('authenticate-'+name,'sage.registry.authenticate',inp,ok,rules=('ID-03','RESOLVE-04'))
    def cardcase(name,card= CARD,ok=True,**controls):
        inp=dict(card_hex=jcs(card).hex(),record=RECORD,now=NOW,clock_trusted=True,expected_peer=DID);inp.update(controls)
        case('card-'+name,'sage.card.verify',inp,ok,rules=('CARD-01','CARD-02','CARD-03'))
    cardcase('valid');cardcase('last-second',now=NOW+299);cardcase('expired',ok=False,now=NOW+300);cardcase('future',ok=False,now=NOW-1);cardcase('clock',ok=False,clock_trusted=False);cardcase('peer',ok=False,expected_peer=DID+'x')
    for name,change in [('version',lambda x:x.update(version='0.9.0')),('record-version',lambda x:x.update(recordVersion='2')),('services',lambda x:x.update(services=[])),('lifetime',lambda x:x.update(expires=NOW+301)),('empty-name',lambda x:x.update(name='')),('name-size',lambda x:x.update(name='a'*129)),('description-size',lambda x:x.update(description='a'*4097)),('null',lambda x:x.update(description=None)),('unknown',lambda x:x.update(keys=[])),('capabilities-duplicate',lambda x:x.update(capabilities=['read','read'])),('capabilities-order',lambda x:x.update(capabilities=['z','a'])),('legacy-proof',lambda x:x['proof'].update(type='Ed25519Signature2020')),('wrong-key',lambda x:x['proof'].update(verificationMethod=DID+'#missing'))]:
        x=copy.deepcopy(CARD);change(x);cardcase(name,signed(x),False)
    x=copy.deepcopy(CARD);x['name']='Tampered';cardcase('signature',x,False)
    unsigned=copy.deepcopy(CARD);sig=unsigned['proof'].pop('proofValue')
    case('card-signature-primitive','signature.verify',dict(algorithm='ed25519',public_key_hex=public(SK).hex(),message_hex=(b'sage-card-0.10.0\0'+jcs(unsigned)).hex(),signature_hex=base64.urlsafe_b64decode(sig+'==').hex()),rules=('CARD-02',))
    for name,r,ok in [('valid',RECORD,True),('no-kem',dict(RECORD,keys=[KEY]),False),('revoked-kem',dict(RECORD,keys=[dict(KEM,state='revoked'),KEY]),False),('expired-kem',dict(RECORD,keys=[dict(KEM,expires=NOW),KEY]),False)]:
        case('kem-select-'+name,'sage.registry.kem.select',dict(record=r,now=NOW),ok,dict(keyid=DID+'#kem-1'),rules=('REG-02',))
    kem0=entry('kem-0','x25519',public(x25519.X25519PrivateKey.from_private_bytes(hashlib.sha256(b'public earlier KEM').digest())),'signing-1')
    for name,first,selected in [('first-ascii',kem0,'kem-0'),('first-revoked',dict(kem0,state='revoked'),'kem-1'),('first-expired',dict(kem0,expires=NOW),'kem-1')]:
        case('kem-select-'+name,'sage.registry.kem.select',dict(record=dict(RECORD,keys=[first,KEM,KEY]),now=NOW),True,dict(keyid=DID+'#'+selected),rules=('REG-02',))
    # Constant-authority fixtures do not contact the network or bless any deployment.
    chain_rid='eip155:1:0x'+'ab'*20
    chain_record=copy.deepcopy(RECORD);chain_record.update(id='did:sage:'+chain_rid+':alice',controller='0x'+'cd'*20,state='created')
    for k in chain_record['keys']:
        k['proof']=dict(signer=chain_record['id']+'#signing-1',value=b64(SK.sign(challenge(chain_rid,'alice',k['name'],k['alg'],base64.urlsafe_b64decode(k['key']+'=')))))
    scenarios=[]
    def scenario(name,actions):
        steps=[];highest=0;tombstone=False;ready=True;effects=dict(observations=0,authorized=0,mutations=0);version=1;state='created'
        def add(op,inp,ok=True,output=None):steps.append(dict(id='step-'+str(len(steps)),operation=op,input=inp,timeout_ms=5000,expected=dict(verdict='ACCEPT' if ok else 'REJECT',output=(output or {}) if ok else {}),effects=copy.deepcopy(effects)))
        add('control.registry.create',dict(record=chain_record,source='fixture-authority',trusted=True,ready=True,highest_finalized_version='0'))
        for a in actions:
            a=copy.deepcopy(a);kind=a.pop('action','observe');ok=True;result={}
            if kind=='restart':ready=False
            elif kind=='ready':ready=True
            elif kind=='mutate':
                ok=a['authorized'] and a['expected_version']==str(version) and version<18446744073709551615 and state!='deactivated'
                if ok:version+=1;state=a['new_state'];effects['mutations']+=1
                result=dict(version=str(version),state=state)
            else:
                x=dict(version='2',state='active',source='fixture-authority',trusted=True,clock_trusted=True,ready=ready,finalized=True,block_hash='aa'*32,keys_block_hash='aa'*32,registry_id='eip155:1:0x'+'ab'*20,operation_started=10,observed=10,gate=10,conflicting=False,lookup=True,transport_ok=True);x.update(a);a=x
                effects['observations']+=1
                v=int(x['version']);ok=ready and x['ready'] and x['trusted'] and x['clock_trusted'] and x['source']=='fixture-authority' and x['registry_id']=='eip155:1:0x'+'ab'*20 and x['operation_started']<=x['observed']<=x['gate'] and x['gate']-x['observed']<=5 and x['finalized'] and x['block_hash']==x['keys_block_hash'] and not x['conflicting'] and x['lookup'] and x['transport_ok'] and v>=highest and not (tombstone and x['state']!='deactivated')
                if ok:
                    highest=max(highest,v);tombstone|=x['state']=='deactivated'
                    if kind=='authorize':ok=x['state']=='active'
                if ok and kind=='authorize':effects['authorized']+=1
                result=dict(state=x['state'],version=x['version'])
            add('subject.call',dict(action=kind,**a),ok,result)
            add('subject.call',dict(action='inspect'),output=dict(highest_finalized_version=str(highest),tombstone=tombstone,ready=ready,version=str(version),state=state))
        scenarios.append(dict(schema_version=2,protocol_version='0.10.0',profile='stateful-scenario',id='registry-'+name,sources=SOURCE,steps=steps))
    scenario('freshness',[dict(action='authorize',gate=15),dict(action='authorize',gate=16)])
    scenario('positive-cache',[dict(action='authorize'),dict(action='authorize',operation_started=11)])
    scenario('rollback',[dict(version='3'),dict(version='2')])
    scenario('restart',[dict(version='3'),dict(action='restart'),dict(action='authorize'),dict(action='ready'),dict(version='2'),dict(version='3')])
    scenario('unfinalized-reorg',[dict(state='deactivated',finalized=False),dict(action='authorize')])
    scenario('finalized-tombstone',[dict(state='deactivated'),dict(action='authorize',version='3')])
    scenario('inactive-resolution',[dict(state='deactivated'),dict(action='authorize',state='deactivated')])
    for field,value in [('trusted',False),('clock_trusted',False),('source','peer-resolver'),('ready',False),('keys_block_hash','bb'*32),('conflicting',True),('lookup',False),('transport_ok',False),('registry_id','eip155:2:0x'+'ab'*20)]:scenario('reject-'+field,[{field:value}])
    scenario('mutations',[dict(action='mutate',authorized=False,expected_version='1',new_state='active'),dict(action='mutate',authorized=True,expected_version='0',new_state='active'),dict(action='mutate',authorized=True,expected_version='1',new_state='active'),dict(action='mutate',authorized=True,expected_version='1',new_state='deactivated'),dict(action='mutate',authorized=True,expected_version='2',new_state='deactivated'),dict(action='mutate',authorized=True,expected_version='3',new_state='active')])
    root=dict(schema_version=1,protocol_version='0.10.0',profile='primitive-foundation',id='sage-registry-records-0.10.0',sources=SOURCE,cases=cases)
    (out/'registry-records.json').write_text(json.dumps(root,indent=2)+'\n')
    folder=out/'registry-scenarios';folder.mkdir(exist_ok=True);manifest=dict(schema_version=1,protocol_version='0.10.0',records_sha256=sha((out/'registry-records.json').read_bytes()),scenarios=[])
    for s in scenarios:
        f=folder/(s['id']+'.json');f.write_text(json.dumps(s,indent=2)+'\n');manifest['scenarios'].append(dict(id=s['id'],file=f.name,sha256=sha(f.read_bytes()),rule_ids=['REG-03'] if s['id'].endswith('mutations') else ['REG-05','RESOLVE-02','RESOLVE-03']))
    (out/'registry-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(len(cases),'cases',len(scenarios),'scenarios',sum(len(s['steps']) for s in scenarios),'steps')
if __name__=='__main__':generate(Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'vectors/0.10.0')
