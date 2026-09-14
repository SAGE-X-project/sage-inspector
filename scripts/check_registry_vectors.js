// Independent Node expectation audit, never a SAGE subject or trusted deployment.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=process.argv[2]||path.join(__dirname,'../vectors/0.10.0');
const read=p=>JSON.parse(fs.readFileSync(path.join(root,p))),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const bytes=x=>Buffer.from(x,'hex'),b64=b=>b.toString('base64url');
const jcs=x=>Buffer.from(JSON.stringify(x,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v));
function decode(s){assert(typeof s==='string'&&/^[A-Za-z0-9_-]*$/.test(s));const b=Buffer.from(s,'base64url');assert.equal(b64(b),s);return b;}
function verify(pub,msg,sig){return crypto.verify(null,msg,crypto.createPublicKey({key:Buffer.concat([bytes('302a300506032b6570032100'),pub]),format:'der',type:'spki'}),sig);}
function exact(x,required,optional=[]){assert(x&&typeof x==='object'&&!Array.isArray(x));assert(required.every(k=>Object.hasOwn(x,k)));assert(Object.keys(x).every(k=>required.includes(k)||optional.includes(k)));assert(!Object.values(x).includes(null));}
function did(id){
 assert(typeof id==='string'&&Buffer.byteLength(id)<=256&&/^[\x00-\x7f]+$/.test(id));
 const p=id.split(':');assert.equal(p[0],'did');assert.equal(p[1],'sage');
 const agent=p.at(-1);assert(/^[a-zA-Z0-9._-]{1,64}$/.test(agent)&&agent!=='.'&&agent!=='..');
 if(p[2]==='web'){assert.equal(p.length,5);const domain=p[3];assert(domain.length<=64&&!/^[0-9.]+$/.test(domain));assert(domain.split('.').every(l=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)));}
 else{assert.equal(p[2],'eip155');assert.equal(p.length,6);assert(/^[1-9][0-9]{0,31}$/.test(p[3]));assert(/^0x[0-9a-f]{40}$/.test(p[4]));}
 return p;
}
function challenge(id,key){const p=did(id),values=[Buffer.from(p.slice(2,-1).join(':')),Buffer.from(p.at(-1)),Buffer.from(key.name),Buffer.from(key.alg),decode(key.key)];return Buffer.concat([Buffer.from('sage-pop-0.10.0'),...values.flatMap(v=>{let n=Buffer.alloc(2);n.writeUInt16BE(v.length);return[n,v];})]);}
const usable=(k,now)=>k.state==='accepted'&&(k.expires===undefined||now<k.expires);
function record(r,now,mode='read'){
 exact(r,['id','controller','keys','services','state','version']);did(r.id);assert(/^[1-9][0-9]*$/.test(r.version)&&BigInt(r.version)<=18446744073709551615n);assert(['created','active','deactivated'].includes(r.state));assert(/^[\x00-\x7f]{1,256}$/.test(r.controller));
 assert(r.keys.length>=1&&r.keys.length<=128&&r.services.length<=16);
 const names=r.keys.map(k=>k.name),materials=r.keys.map(k=>k.key);assert.deepEqual(names,[...names].sort());assert.equal(new Set(names).size,names.length);assert.equal(new Set(materials).size,materials.length);
 for(const k of r.keys){exact(k,['name','alg','key','proof','state'],['expires']);assert(/^[A-Za-z0-9_-]{1,32}$/.test(k.name));assert(['ed25519','x25519'].includes(k.alg));assert.equal(decode(k.key).length,32);assert(['accepted','revoked'].includes(k.state));if(k.expires!==undefined)assert(Number.isSafeInteger(k.expires)&&k.expires>=0);exact(k.proof,['signer','value']);assert(k.proof.value.length<=87);}
 for(const k of [...r.keys.filter(k=>k.alg==='ed25519'),...r.keys.filter(k=>k.alg==='x25519')]){
  const signer=r.keys.find(s=>r.id+'#'+s.name===k.proof.signer);assert(signer&&signer.alg==='ed25519');
  if(k.alg==='ed25519')assert.equal(k.proof.signer,r.id+'#'+k.name);
  if(k.alg==='x25519'&&mode!=='read')assert(usable(signer,now));
  assert(verify(decode(signer.key),challenge(r.id,k),decode(k.proof.value)));
 }
 const sn=r.services.map(s=>s.name);assert.deepEqual(sn,[...sn].sort());assert.equal(new Set(sn).size,sn.length);
 for(const s of r.services){exact(s,['name','type','uri']);assert(/^[A-Za-z0-9_-]{1,32}$/.test(s.name)&&!names.includes(s.name));assert(/^[\x00-\x7f]{1,64}$/.test(s.type));assert(s.uri.length<=2048&&/^[\x00-\x7f]+$/.test(s.uri));const u=new URL(s.uri);assert(u.protocol==='https:'&&!u.username&&!u.password&&!u.hash);}
 assert(jcs(r).length<=65536);
}
function authenticate(x){const r=x.record;record(r,x.now);assert.equal(r.state,'active');assert.equal(x.sender,r.id);assert.equal(x.expected_peer,r.id);const k=r.keys.find(k=>r.id+'#'+k.name===x.keyid);assert(k&&k.alg==='ed25519'&&usable(k,x.now)&&k.alg===x.alg);}
function card(x){
 const raw=bytes(x.card_hex);assert(raw.length<=65536);const c=JSON.parse(raw);exact(c,['version','id','recordVersion','name','services','issued','expires','proof'],['description','capabilities']);assert.equal(c.version,'0.10.0');did(c.id);assert.equal(c.id,x.expected_peer);assert(x.clock_trusted);
 assert(Number.isSafeInteger(c.issued)&&c.issued>=0&&Number.isSafeInteger(c.expires)&&c.expires>=0);assert(c.issued<=x.now&&x.now<c.expires&&c.expires-c.issued<=300);
 assert(typeof c.name==='string'&&Buffer.byteLength(c.name)>0&&Buffer.byteLength(c.name)<=128);if(c.description!==undefined)assert(typeof c.description==='string'&&Buffer.byteLength(c.description)<=4096);
 if(c.capabilities!==undefined){assert(c.capabilities.length<=64);assert(c.capabilities.every(s=>/^[\x00-\x7f]{1,64}$/.test(s)));assert.equal(new Set(c.capabilities).size,c.capabilities.length);assert.deepEqual(c.capabilities,[...c.capabilities].sort());}
 exact(c.proof,['type','verificationMethod','alg','proofValue']);assert.equal(c.proof.type,'SageAgentCardSignature0_10_0');assert(c.proof.proofValue.length<=87);
 authenticate({record:x.record,now:x.now,keyid:c.proof.verificationMethod,sender:c.id,expected_peer:x.expected_peer,alg:c.proof.alg});assert.equal(c.recordVersion,x.record.version);assert.deepEqual(c.services,x.record.services);
 const sig=decode(c.proof.proofValue);delete c.proof.proofValue;const key=x.record.keys.find(k=>c.id+'#'+k.name===c.proof.verificationMethod);assert(verify(decode(key.key),Buffer.concat([Buffer.from('sage-card-0.10.0\0'),jcs(c)]),sig));
}
const suite=read('registry-records.json');assert.equal(new Set(suite.cases.map(c=>c.id)).size,suite.cases.length);
for(const c of suite.cases){assert(['sage.did.validate','signature.verify','sage.registry.pop.verify','sage.registry.record.verify','sage.registry.authenticate','sage.card.verify','sage.registry.resolve','sage.registry.kem.select'].includes(c.operation));let ok=true,output={valid:true};const x=c.input;
 try{
  if(c.operation==='sage.did.validate')did(x.did);
  else if(c.operation==='signature.verify')assert(verify(bytes(x.public_key_hex),bytes(x.message_hex),bytes(x.signature_hex)));
  else if(c.operation==='sage.registry.pop.verify')assert(verify(bytes(x.public_key_hex),challenge(x.did,{name:x.name,alg:x.alg,key:b64(bytes(x.public_key_hex))}),bytes(x.signature_hex)));
  else if(c.operation==='sage.registry.record.verify'){const r=JSON.parse(bytes(x.record_hex));record(r,x.now,x.mode);assert.equal(r.id,x.expected_did);}
  else if(c.operation==='sage.registry.authenticate')authenticate(x);
  else if(c.operation==='sage.registry.kem.select'){record(x.record,x.now);const k=x.record.keys.find(k=>k.alg==='x25519'&&usable(k,x.now));assert(x.record.state==='active'&&k);output={keyid:x.record.id+'#'+k.name};}
  else if(c.operation==='sage.card.verify')card(x);
  else if(c.operation==='sage.registry.resolve'){record(x.record,x.now);assert(x.record.state!=='active');output={state:x.record.state,version:x.record.version,verification_methods:[],authentication:[],assertion_method:[],key_agreement:[],services:x.record.services};}
  else throw Error('unknown fixture operation');
 }catch(e){ok=false;}
 assert.deepEqual(c.expected,{verdict:ok?'ACCEPT':'REJECT',output:ok?output:{}},c.id);
}
let total=0;const manifest=read('registry-manifest.json');assert.equal(manifest.records_sha256,sha(fs.readFileSync(path.join(root,'registry-records.json'))));
assert.equal(new Set(manifest.scenarios.map(x=>x.id)).size,17);
for(const m of manifest.scenarios){const file=path.join(root,'registry-scenarios',m.file);assert.equal(m.sha256,sha(fs.readFileSync(file)));const f=JSON.parse(fs.readFileSync(file));assert.equal(m.id,f.id);
 let highest=0n,tombstone=false,ready=true,version=1n,state='created',effects={observations:0,authorized:0,mutations:0};
 for(const s of f.steps){const x=s.input;let ok=true,output={};
  if(s.operation==='control.registry.create'){record(x.record,1700000000);}
  else if(x.action==='inspect')output={highest_finalized_version:String(highest),tombstone,ready,version:String(version),state};
  else if(x.action==='restart')ready=false;
  else if(x.action==='ready')ready=true;
  else if(x.action==='mutate'){ok=x.authorized&&BigInt(x.expected_version)===version&&version<18446744073709551615n&&state!=='deactivated';if(ok){version++;state=x.new_state;effects.mutations++;}output={version:String(version),state};}
  else{effects.observations++;const v=BigInt(x.version);ok=ready&&x.ready&&x.trusted&&x.clock_trusted&&x.source==='fixture-authority'&&x.registry_id==='eip155:1:0x'+'ab'.repeat(20)&&x.operation_started<=x.observed&&x.observed<=x.gate&&x.gate-x.observed<=5&&x.finalized&&x.block_hash===x.keys_block_hash&&!x.conflicting&&x.lookup&&x.transport_ok&&v>=highest&&!(tombstone&&x.state!=='deactivated');
   if(ok){highest=v>highest?v:highest;tombstone||=x.state==='deactivated';if(x.action==='authorize')ok=x.state==='active';}
   if(ok&&x.action==='authorize')effects.authorized++;output={state:x.state,version:x.version};
  }
  assert.deepEqual(s.expected,{verdict:ok?'ACCEPT':'REJECT',output:ok?output:{}},m.id+':'+s.id);assert.deepEqual(s.effects,effects,m.id+':'+s.id);total++;
 }
}
assert.equal(suite.cases.length,94);assert.equal(total,83);
console.log(`${suite.cases.length} registry/Card cases and 17 scenarios (${total} steps) audited; synthetic authority only.`);
