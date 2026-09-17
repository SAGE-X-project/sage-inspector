"""Project frozen observations onto the trusted-source gate, not deployed chain proofs."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
REG='eip155:1:0x'+'ab'*20
DID='did:sage:'+REG+':alice'
CFG=dict(source='fixture-authority',registry=REG,network='1',blockchain=True)
old=json.loads((ROOT/'vectors/0.10.0/registry-scenarios/registry-freshness.json').read_text())
record=old['steps'][0]['input']['record']
KEYS=[dict(name=k['name'],alg=k['alg'],material=base64.urlsafe_b64decode(k['key']+'='*(-len(k['key'])%4)).hex(),state=k['state']) for k in record['keys']]
def seal(s):
    s=copy.deepcopy(s)
    s['digest']=hashlib.sha256(json.dumps({k:s[k] for k in ['did','version','state','keys']},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return s
BASE=seal(dict(source=CFG['source'],registry=REG,network='1',did=DID,version='2',state='active',ready=True,validated=True,finalized=True,conflicting=False,acquired_ms=10000,block_hash='aa'*32,keys_block_hash='aa'*32,keys=KEYS))
def call(action,s=None,verdict='ACCEPT',output=None,**extra):
    s=copy.deepcopy(s or BASE)
    if output is None:
        if verdict!='ACCEPT':output={}
        elif action=='observe':output=dict(state=s['state'],version=s['version'])
        elif action=='select':output=dict(signing_keyid=s['did']+'#signing-1',kem_keyid=s['did']+'#kem-1' if extra.get('require_kem',False) else '')
        elif action=='check':output=dict(valid=True)
        else:output={}
    q=dict(action=action,did=s['did'],snapshot=s,times=[dict(mono_ms=10000,unix=100)]*3,clock_ok=True,source_ok=True,signing_url=s['did']+'#signing-1',require_kem=False)
    q.update(extra)
    if action != "select":
        q.pop("signing_url");q.pop("require_kem")
    return dict(request=q,expected=dict(verdict=verdict,output=output))
def inspect(version='0',terminal=False,did=DID):return dict(request=dict(action='inspect',did=did),expected=dict(verdict='ACCEPT',output=dict(highest_finalized_version=version,tombstone=terminal)))
cases=[]
for path in sorted((ROOT/'vectors/0.10.0/registry-scenarios').glob('*.json')):
    if path.stem=='registry-mutations':continue
    old=json.loads(path.read_text());steps=[]
    for step in old['steps'][1:]:
        i=step['input'];action=i['action']
        if action=='ready':continue # readiness is verified on every new Source.read, never cached.
        if action=='restart':steps.append(dict(request=dict(action='restart'),expected=dict(verdict='ACCEPT',output={})));continue
        if action=='inspect':
            o=step['expected']['output'];steps.append(inspect(o['highest_finalized_version'],o['tombstone']));continue
        s=seal(dict(BASE,version=i['version'],state=i['state'],source=i['source'],registry=i['registry_id'],ready=i['ready'],finalized=i['finalized'],conflicting=i['conflicting'],acquired_ms=i['observed']*1000,block_hash=i['block_hash'],keys_block_hash=i['keys_block_hash']))
        times=[dict(mono_ms=i['operation_started']*1000,unix=100),dict(mono_ms=i['gate']*1000,unix=100),dict(mono_ms=i['gate']*1000,unix=100)]
        op='select' if action=='authorize' else 'observe'
        steps.append(call(op,s,step['expected']['verdict'],times=times,clock_ok=i['clock_trusted'],source_ok=i['trusted'] and i['lookup'] and i['transport_ok']))
    cases.append(dict(id=path.stem,source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),steps=steps))
def add(name,steps):cases.append(dict(id=name,steps=steps))
add('exact-signing-url',[call('select',verdict='REJECT',signing_url=DID+'#missing')])
add('kem-required',[call('select',require_kem=True)])
no_kem=seal(dict(BASE,keys=[KEYS[1]]))
add('signing-without-kem',[call('select',no_kem),call('select',no_kem,'REJECT',require_kem=True)])
for name,change in [('revoked-signing',dict(state='revoked')),('changed-material',dict(material='d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')),('changed-expiry',dict(expires=200)),('changed-algorithm',dict(alg='x25519'))]:
    s=copy.deepcopy(BASE);s['version']='3';s['keys'][1].update(change);s=seal(s)
    add(name,[call('select',require_kem=True),call('check',s,'REJECT'),inspect('3')])
s=copy.deepcopy(BASE);s['keys'][0]['state']='revoked';s['version']='3';s=seal(s)
add('revoked-kem',[call('select',require_kem=True),call('check',s,'REJECT')])
s=copy.deepcopy(BASE);s['keys'].insert(0,dict(name='aaa-kem',alg='x25519',material='03'*32,state='accepted'));s['version']='3';s=seal(s)
add('unrelated-key-addition',[call('select',require_kem=True),call('check',s),call('select',s,require_kem=True,output=dict(signing_keyid=DID+'#signing-1',kem_keyid=DID+'#aaa-kem'))])
s=seal(dict(BASE,version='3'));s['digest']='bb'*32
add('unrelated-record-update',[call('select',require_kem=True),call('check',s)])
s=copy.deepcopy(BASE);s['keys'][1]['expires']=101;s=seal(s)
add('expiry-equality',[call('select',s),call('check',s,'REJECT',times=[dict(mono_ms=10000,unix=101)]*3)])
s=copy.deepcopy(BASE);s['digest']='bb'*32
add('same-version-conflict',[call('observe'),call('observe',s,'REJECT'),inspect('2')])
add('unvalidated-record',[call('observe',dict(BASE,validated=False),'REJECT'),inspect()])
add('network-binding',[call('observe',dict(BASE,network='2'),'REJECT'),inspect()])
add('future-acquisition',[call('observe',dict(BASE,acquired_ms=11000),'REJECT'),inspect()])
add('clock-rollback',[call('observe'),call('observe',verdict='REJECT',times=[dict(mono_ms=9999,unix=100)]*3)])
add('storage-delay-and-refresh',[call('select',verdict='REJECT',times=[dict(mono_ms=10000,unix=100),dict(mono_ms=10000,unix=100),dict(mono_ms=15001,unix=100)]),inspect('2'),call('select',dict(BASE,acquired_ms=16000),times=[dict(mono_ms=16000,unix=100)]*3)])
add('scope-isolation',[call('observe',seal(dict(BASE,version='3'))),call('observe',seal(dict(BASE,did='did:sage:'+REG+':bob'))),inspect('3'),inspect('2',did='did:sage:'+REG+':bob')])
add('maximum-version',[call('observe',seal(dict(BASE,version=str(2**64-1)))),call('observe',verdict='REJECT'),inspect(str(2**64-1))])
for value in ['0','01','18446744073709551616','-1']:
    add('invalid-version-'+value,[call('observe',seal(dict(BASE,version=value)),'REJECT'),inspect()])
fixture=dict(scope='Trusted-source and clock injection; full record proofs and deployed finality are external prerequisites. REG-03 mutations excluded.',config=CFG,cases=cases)
text=json.dumps(fixture,indent=2)+'\n';path=ROOT/'vectors/0.10.0/registry010.json'
if '--check' in sys.argv:assert path.read_text()==text,'registry gate fixture drift'
else:path.write_text(text)
print(len(cases),'cases',sum(len(c['steps']) for c in cases),'steps')
