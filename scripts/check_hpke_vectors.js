// Independent ECMAScript/Node calculation. Not a SAGE subject implementation.
const fs=require('node:fs'), path=require('node:path'), crypto=require('node:crypto');
const root=process.argv[2] || path.join(__dirname,'../vectors/0.10.0');
const H=x=>crypto.createHash('sha256').update(x).digest();
const M=(k,x)=>crypto.createHmac('sha256',k).update(x).digest();
const cat=(...x)=>Buffer.concat(x.map(v=>Buffer.isBuffer(v)?v:Buffer.from(v)));
const hex=x=>Buffer.from(x,'hex');
function canonical(o) {
  if(Array.isArray(o)) return '['+o.map(canonical).join(',')+']';
  if(o!==null && typeof o==='object') return '{'+Object.keys(o).sort().map(k=>JSON.stringify(k)+':'+canonical(o[k])).join(',')+'}';
  return JSON.stringify(o);
}
function fail(reason){throw new Error(reason);}
function exact(o,keys,reason='schema') {if(!o || typeof o!=='object' || Array.isArray(o) || Object.keys(o).sort().join('|')!==[...keys].sort().join('|'))fail(reason);}
function binary(s,n){if(typeof s!=='string'||!/^[A-Za-z0-9_-]*$/.test(s))fail('schema');const b=Buffer.from(s,'base64url');if(b.length!==n||b.toString('base64url')!==s)fail('schema');return b;}
function expand(k,info,n=32){let prev=Buffer.alloc(0),out=Buffer.alloc(0);for(let c=1;out.length<n;c++){prev=M(k,cat(prev,info,Buffer.from([c])));out=cat(out,prev);}return out.subarray(0,n);}
const KS=hex('4b454d0020'), HS=hex('48504b45002000010003');
const le=(suite,salt,label,data)=>M(salt,cat('HPKE-v1',suite,label,data));
function lx(suite,k,label,data){return expand(k,cat(hex('0020'),'HPKE-v1',suite,label,data));}
function priv(sk,type='x25519'){return crypto.createPrivateKey({format:'der',type:'pkcs8',key:cat(hex(type==='x25519'?'302e020100300506032b656e04220420':'302e020100300506032b657004220420'),sk)});}
function pub(sk){return crypto.createPublicKey(priv(sk)).export({format:'der',type:'spki'}).subarray(-32);}
function dh(sk,pk){try{return crypto.diffieHellman({privateKey:priv(sk),publicKey:crypto.createPublicKey({format:'der',type:'spki',key:cat(hex('302a300506032b656e032100'),pk)})});}catch{fail('invalid-dh');}}
function hpke(sharedDH,enc,pkR,info,ec){
 const shared=lx(KS,le(KS,Buffer.alloc(0),'eae_prk',sharedDH),'shared_secret',cat(enc,pkR));
 const kctx=cat(hex('00'),le(HS,Buffer.alloc(0),'psk_id_hash',Buffer.alloc(0)),le(HS,Buffer.alloc(0),'info_hash',info));
 const secret=le(HS,shared,'secret',Buffer.alloc(0)), es=lx(HS,secret,'exp',kctx), exported=lx(HS,es,'sec',ec);
 return {kem_shared_secret_hex:shared.toString('hex'),key_schedule_context_hex:kctx.toString('hex'),hpke_secret_hex:secret.toString('hex'),exporter_secret_hex:es.toString('hex'),exporter_hex:exported.toString('hex')};
}
function combine(exp,ss,th){const prk=M(th,cat(exp,ss)),seed=expand(prk,cat('sage-hpke-combiner|0.10.0',th)),ak=expand(seed,cat('sage-hpke-ack|0.10.0',th));return {prk_hex:prk.toString('hex'),seed_hex:seed.toString('hex'),ack_key_hex:ak.toString('hex'),ack_tag_hex:M(ak,th).toString('hex'),sid:H(cat('sage-session|0.10.0',th)).subarray(0,16).toString('base64url')};}
const bkeys=['v','ctx','initDid','respDid','initKid','respKid','kemKid','suite','combiner','nonce'];
const ikeys=[...bkeys,'task','enc','ephC'];
function binding(init){const b={};for(const k of bkeys)b[k]=init[k];return b;}
function verifySig(pubkey,msg,sig){return crypto.verify(null,Buffer.from(msg),{format:'der',type:'spki',key:cat(hex('302a300506032b6570032100'),pubkey)},sig);}
function derive(i){
 exact(i.binding,bkeys,'binding');
 if(i.binding.v!=='0.10.0'||i.binding.suite!=='hpke-base+x25519+hkdf-sha256'||i.binding.combiner!=='e2e-x25519-hkdf-v1')fail('binding');
 const skR=hex(i.recipient_private_hex),skE=hex(i.hpke_ephemeral_private_hex),c=hex(i.client_ephemeral_private_hex),s=hex(i.server_ephemeral_private_hex);
 const pkR=pub(skR),enc=pub(skE),pc=pub(c),ps=pub(s),info=cat('sage-hpke-info|0.10.0\n',canonical(i.binding)),ec=cat('sage-hpke-export|0.10.0\n',H(info));
 if(!dh(skR,enc).equals(dh(skE,pkR))||!dh(c,ps).equals(dh(s,pc)))fail('agreement');
 const h=hpke(dh(skR,enc),enc,pkR,info,ec),init={...i.binding,task:'hpke/init@0.10.0',enc:enc.toString('base64url'),ephC:pc.toString('base64url')},t={...init,ephS:ps.toString('base64url'),kid:i.kid},th=H(canonical(t)),ss=dh(c,ps),f=combine(hex(h.exporter_hex),ss,th);
 const p={v:'0.10.0',task:'hpke/complete@0.10.0',transcript:t,ackTagB64:hex(f.ack_tag_hex).toString('base64url')};
 const signing=priv(hex(i.responder_signing_private_hex),'ed25519');
 p.sigB64=crypto.sign(null,cat('sage-hpke-complete|0.10.0\n',canonical(p)),signing).toString('base64url');
 return {...h,...f,binding_hex:Buffer.from(canonical(i.binding)).toString('hex'),info_hex:info.toString('hex'),export_context_hex:ec.toString('hex'),enc_hex:enc.toString('hex'),ephemeral_c_hex:pc.toString('hex'),ephemeral_s_hex:ps.toString('hex'),initiation_hex:Buffer.from(canonical(init)).toString('hex'),completion_hex:Buffer.from(canonical(p)).toString('hex'),transcript_hex:Buffer.from(canonical(t)).toString('hex'),th_hex:th.toString('hex'),ss_e2e_hex:ss.toString('hex')};
}
function completion(i){
 const raw=hex(i.completion_hex);if(raw.length>16384)fail('bounds');
 const p=JSON.parse(raw.toString()),pending=i.pending,init=JSON.parse(hex(pending.initiation_hex).toString());
 exact(p,['v','task','transcript','ackTagB64','sigB64']);
 if(p.v!=='0.10.0'||p.task!=='hpke/complete@0.10.0')fail('schema');
 exact(p.transcript,[...ikeys,'ephS','kid']);
 for(const k of ikeys)if(canonical(p.transcript[k])!==canonical(init[k]))fail('echo');
 if(!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(p.transcript.kid))fail('schema');
 const ack=binary(p.ackTagB64,32),sig=binary(p.sigB64,64),ps=binary(p.transcript.ephS,32),unsigned={...p};delete unsigned.sigB64;
 if(!verifySig(hex(pending.responder_signing_public_hex),cat('sage-hpke-complete|0.10.0\n',canonical(unsigned)),sig))fail('signature');
 const b=binding(init),info=cat('sage-hpke-info|0.10.0\n',canonical(b)),ec=cat('sage-hpke-export|0.10.0\n',H(info)),enc=binary(init.enc,32),pkR=hex(pending.recipient_public_hex);
 const h=hpke(dh(hex(pending.hpke_ephemeral_private_hex),pkR),enc,pkR,info,ec),ss=dh(hex(pending.client_ephemeral_private_hex),ps),th=H(canonical(p.transcript)),f=combine(hex(h.exporter_hex),ss,th);
 if(!crypto.timingSafeEqual(ack,hex(f.ack_tag_hex)))fail('ack');
 return {seed_hex:f.seed_hex,th_hex:th.toString('hex'),sid:f.sid};
}
function observe(c){const i=c.input;switch(c.operation){
 case 'sage.hpke.derive':return derive(i);
 case 'sage.hpke.complete.verify':return completion(i);
 case 'rfc9180.export':{let shared;try{shared=dh(hex(i.private_key_hex),hex(i.enc_hex));}catch{fail('invalid-kem');}return {exporter_hex:hpke(shared,hex(i.enc_hex),pub(hex(i.private_key_hex)),hex(i.info_hex),hex(i.export_context_hex)).exporter_hex};}
 case 'sage.hpke.combine':{const ss=hex(i.ss_e2e_hex);if(ss.length!==32||ss.equals(Buffer.alloc(32)))fail('invalid-combiner-input');return {seed_hex:combine(hex(i.exporter_hex),ss,hex(i.th_hex)).seed_hex};}
 case 'x25519.exchange':return {shared_secret_hex:dh(hex(i.private_key_hex),hex(i.public_key_hex)).toString('hex')};
 case 'jcs.canonicalize':return {canonical_hex:Buffer.from(canonical(JSON.parse(hex(i.document_hex).toString()))).toString('hex')};
 case 'signature.verify':if(!verifySig(hex(i.public_key_hex),hex(i.message_hex),hex(i.signature_hex)))fail('signature');return {valid:true};
 default:fail('unknown operation');
}}
const reasons=JSON.parse(fs.readFileSync(path.join(root,'hpke-rejection-reasons.json')));let count=0;
for(const file of ['hpke-primitives.json','hpke-schedule.json']){
 const suite=JSON.parse(fs.readFileSync(path.join(root,file)));
 for(const c of suite.cases){let result,reason=null;try{result=observe(c);}catch(e){reason=e.message;}
  if(c.expected.verdict==='ACCEPT'){if(reason||canonical(result)!==canonical(c.expected.output))throw Error(c.id+': '+reason+' or intermediate mismatch');}
  else if(!reason||reason!==reasons[c.id])throw Error(c.id+': '+reason+' expected '+reasons[c.id]);
  count++;
 }
}
// Independent lifecycle model audits scenario expectations, not real erasure/effects.
let scenarios=0;
for(const file of fs.readdirSync(path.join(root,'hpke-scenarios')).filter(x=>x.endsWith('.json'))){
 const sc=JSON.parse(fs.readFileSync(path.join(root,'hpke-scenarios',file)));let state='NEW',control=null,effects={sessions_created:0,pending_destroyed:0};
 for(const st of sc.steps){let output={},verdict='ACCEPT';const i=st.input;
  if(st.operation==='control.hpke.pending'){control=i;state='INIT_SENT';output={state};}
  else if(i.action==='hpke.complete'){
   const wasPending=state==='INIT_SENT';
   try{if(!wasPending||!i.bound_keys_current||!i.outer_response_authenticated||i.utc>=control.initiation_expires||i.monotonic-control.emitted_monotonic>=300)fail('deadline/key');const c=completion({pending:control.pending,completion_hex:i.completion_hex});state='ESTABLISHED';effects.sessions_created++;output={state,sid:c.sid};}
   catch{verdict='REJECT';state='CLOSED';}
   if(wasPending)effects.pending_destroyed++;
  }else if(i.action==='hpke.inspect')output={state,pending_present:false};else fail('scenario operation');
  if(verdict!==st.expected.verdict||canonical(output)!==canonical(st.expected.output)||canonical(effects)!==canonical(st.effects))throw Error(sc.id+'/'+st.id);
 }
 scenarios++;
}
console.log(`${count} HPKE primitive/composition cases and ${scenarios} lifecycle fixtures independently audited`);
