// Independent Node crypto audit. No SAGE or Python implementation is imported.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=process.argv[2]||path.join(__dirname,'../vectors/0.10.0');
const read=p=>JSON.parse(fs.readFileSync(path.join(root,p)));
const bytes=s=>Buffer.from(s,'hex'), sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const u64=n=>{let b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(n));return b;};
const u32=n=>{let b=Buffer.alloc(4);b.writeUInt32BE(n);return b;};
function key(x,seq){
 const info=Buffer.concat([Buffer.from('sage-'+x.direction+'-key|0.10.0'),bytes(x.th_hex),u64(seq/256n)]);
 // One block is sufficient for L=32. No HKDF-Extract on the seed.
 return crypto.createHmac('sha256',bytes(x.seed_hex)).update(info).update(Buffer.from([1])).digest();
}
function aad(x,seq,caller){return Buffer.concat([Buffer.from('sage-record|0.10.0'),bytes(x.th_hex),Buffer.from([x.direction==='s2c'?1:0]),u64(seq),u32(caller.length),caller]);}
let count=0;
for(const c of read('session-records.json').cases){
 const x=c.input;let expected;
 if(c.operation==='sage.session.key') expected={verdict:'ACCEPT',output:{key_hex:key(x,BigInt(x.seq)).toString('hex'),generation:Math.floor(x.seq/256)}};
 else if(c.operation==='sage.session.record.seal'){
  const p=Buffer.alloc(x.plaintext.length,x.plaintext.byte),caller=bytes(x.caller_aad_hex),nonce=Buffer.alloc(12);
  const cipher=crypto.createCipheriv('chacha20-poly1305',key(x,0n),nonce,{authTagLength:16});
  cipher.setAAD(aad(x,0n,caller));
  const wire=Buffer.concat([u64(0),nonce,cipher.update(p),cipher.final(),cipher.getAuthTag()]);
  expected=p.length>8388572||caller.length>4033?{verdict:'REJECT',output:{}}:{verdict:'ACCEPT',output:{record_sha256:sha(wire),record_bytes:wire.length}};
 }else{
  const w=bytes(x.record_hex),caller=bytes(x.caller_aad_hex);
  try{
   assert(w.length>=36 && w.length<=8388608 && caller.length<=4033);
   const seq=w.readBigUInt64BE();assert(seq<1000n);
   assert.deepEqual(w.subarray(8,20),Buffer.concat([Buffer.alloc(4),u64(seq)]));
   const d=crypto.createDecipheriv('chacha20-poly1305',key(x,seq),w.subarray(8,20),{authTagLength:16});
   d.setAAD(aad(x,seq,caller));d.setAuthTag(w.subarray(-16));
   expected={verdict:'ACCEPT',output:{plaintext_hex:Buffer.concat([d.update(w.subarray(20,-16)),d.final()]).toString('hex')}};
  }catch{expected={verdict:'REJECT',output:{}};}
 }
 assert.deepEqual(c.expected,expected,c.id);count++;
}
// This executable state model checks fixture expectations only. It is not a
// core adapter, nor evidence of scheduling, registry authority, or key erasure.
let scenarios=0,steps=0;
for(const name of fs.readdirSync(path.join(root,'session-scenarios')).sort()){
 const f=read('session-scenarios/'+name);let context,state,send=0,now=0,last=0,seen=new Set();
 let effects={accepted:0,emitted:0,allocated:0,dispatch:0,confirmations:0,closed:0};
 function close(){if(state!=='CLOSED')effects.closed++;state='CLOSED';}
 for(const s of f.steps){
  let verdict='ACCEPT',output={};const x=s.input,a=x.action;
  if(s.operation==='control.session.create'){
   context=x;state=x.state;assert.equal(x.created_monotonic,0);assert.equal(x.idle_monotonic,0);output={state};
   assert.equal(x.sid,Buffer.from(sha(Buffer.concat([Buffer.from('sage-session|0.10.0'),bytes(x.th_hex)])),'hex').subarray(0,16).toString('base64url'));
  }else if(s.operation==='control.clock.set'){assert(x.monotonic>=now);now=x.monotonic;}
  else if(a==='inspect')output={state,next_send:send,received:[...seen].sort((a,b)=>a-b),last_activity:last,keys_available:state!=='CLOSED'};
  else if(a==='close'||a==='restart')close();
  else if(a==='registry'){if(x.change!=='unrelated')close();}
  else{
   if(x.commit_monotonic!==undefined){assert(x.commit_monotonic>=now);now=x.commit_monotonic;}
   if(now>=3600||now-last>=600||(state==='RESPONSE_SENT'&&now>=300))close();
   if(state==='CLOSED')verdict='REJECT';
   else if(a==='send'||a==='parallel-send'){
    const n=x.count||1;
    if(state==='RESPONSE_SENT')verdict='REJECT';
    else if(send+n>1000){close();verdict='REJECT';}
    else{output={sequences:Array.from({length:n},(_,i)=>send+i)};send+=n;effects.allocated+=n;if(!x.transport_failure){effects.emitted+=n;last=now;}}
   }else if(a==='retransmit'){
    if(x.changed_plaintext)verdict='REJECT';else{output={identical_ciphertext:true};effects.emitted++;last=now;}
   }else{
    assert(a==='receive'||a==='parallel-receive');const n=x.seq||0;
    const w=bytes(x.record_hex);assert.equal(w.readBigUInt64BE(),BigInt(n));
    const direction=context.local_role==='responder'?'c2s':'s2c';
    const recordInput={...context,direction};let authentic=true;
    try {const d=crypto.createDecipheriv('chacha20-poly1305',key(recordInput,BigInt(n)),w.subarray(8,20),{authTagLength:16});d.setAAD(aad(recordInput,BigInt(n),bytes(x.caller_aad_hex)));d.setAuthTag(w.subarray(-16));assert.equal(Buffer.concat([d.update(w.subarray(20,-16)),d.final()]).toString(),'public session record');}catch{authentic=false;}
    assert.equal(authentic,x.invalid!=='tag');
    const t=context.tuple,initiator=direction==='c2s';
    const required={version:t.v,context_id:t.ctx,session_id:context.sid,did:initiator?t.initDid:t.respDid,recipient:initiator?t.respDid:t.initDid,kid:initiator?t.initKid:t.respKid};
    const bound=JSON.stringify(required)===JSON.stringify(x.envelope_projection)&&x.sender_role===(initiator?'initiator':'responder');
    if(n>=1000||seen.has(n)||!authentic||!bound||!x.signature_verified)verdict='REJECT';
    else{seen.add(n);effects.accepted++;last=now;if(state==='RESPONSE_SENT'){state='ESTABLISHED';effects.confirmations++;}if(!x.application_reject)effects.dispatch++;output={accepted:1,rejected:(x.copies||1)-1,verdicts:['ACCEPT',...Array((x.copies||1)-1).fill('REJECT')]};}
   }
  }
  if(s.operation==='subject.parallel')assert.equal(x.barrier,'before-atomic-commit');
  assert.deepEqual(s.expected,{verdict,output},name+':'+s.id);assert.deepEqual(s.effects,effects,name+':'+s.id+' effects');steps++;
 }
 scenarios++;
}
assert.equal(count,55);assert.equal(scenarios,37);assert.equal(steps,248);
const manifest=read('session-manifest.json');
assert.equal(manifest.records_sha256,sha(fs.readFileSync(path.join(root,'session-records.json'))));
assert.equal(new Set(manifest.scenarios.map(s=>s.id)).size,scenarios);
for(const s of manifest.scenarios){assert.equal(s.sha256,sha(fs.readFileSync(path.join(root,'session-scenarios',s.file))));assert.equal(read('session-scenarios/'+s.file).id,s.id);}
console.log(`${count} records and ${scenarios} scenarios (${steps} steps) independently audited; no core certification.`);
