"""Spec-derived lifecycle expectations and independent Node public-key controls."""
import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
js="""const c=require('crypto');let out={};for(let n of [1,2]){let k=c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,n)]),format:'der',type:'pkcs8'});out[n]=c.createPublicKey(k).export({format:'der',type:'spki'}).subarray(-32).toString('hex')}process.stdout.write(JSON.stringify(out));"""
keys=json.loads(subprocess.check_output(['node','-e',js],text=True))
cases=[]
def add(name,accept=False,**extra):cases.append(dict(id=name,accept=accept,**extra))
add('valid',True)
for mutation in ['outer-signature','inner-signature','ack','echo','request-hash','message-id','recipient','signing-key','response-nonce','unknown-wire','unknown-completion','duplicate-wire','duplicate-completion','duplicate-transcript','null-transcript','trailing-wire','noncanonical-completion']:
 add(mutation,mutation=mutation)
for mode in ['source-error','revoke-init','revoke-resp','revoke-kem','changed-material','clock-error','store-error','store-delay']:
 add(mode,mode=mode)
add('unrelated-key',True,mode='unrelated')
add('monotonic-before',True,mono_ms=299999)
add('monotonic-equality',mono_ms=300000)
add('utc-before',True,unix=399)
add('utc-equality',unix=400)
add('clock-rollback',mono_ms=-1)
add('completion-expiry',response_ttl=1,unix=101)
add('initiation-expiry',init_ttl=1,unix=101)
add('pending-abandoned',abandon=True)
add('endpoint-closed',endpoint_close=True)
paths=sorted((ROOT/'vectors/0.10.0/hpke-scenarios').glob('*.json'))
f=dict(scope='Fresh locally signed metadata-free plain handshake; synthetic registry/clock and replay faults. Not HTTP, durable replay deployment or provisional record confirmation.',public_keys=keys,sources={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},cases=cases)
encoded=json.dumps(f,indent=2)+'\n';p=ROOT/'vectors/0.10.0/completion010.json'
if '--check' in sys.argv:assert p.read_text()==encoded
else:p.write_text(encoded)
print(len(cases),'completion scenarios')
