// Independent Node expectation audit. No SAGE core and no production Guard.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=process.argv[2]||path.join(__dirname,'../vectors/0.10.0');
const read=p=>JSON.parse(fs.readFileSync(path.join(root,p))),bytes=x=>Buffer.from(x,'hex'),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const jcs=x=>Buffer.from(JSON.stringify(x,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v));
const hash=x=>sha(jcs(x)),decode=s=>{assert(/^[A-Za-z0-9_-]+$/.test(s));const b=Buffer.from(s,'base64url');assert.equal(b.toString('base64url'),s);return b;};
const exact=(x,keys)=>{assert(x&&typeof x==='object'&&!Array.isArray(x));assert.deepEqual(Object.keys(x).sort(),[...keys].sort());};
const uuid=s=>assert(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s));
const hex=s=>assert(/^[0-9a-f]{64}$/.test(s));
const verify=(pub,msg,sig)=>crypto.verify(null,msg,crypto.createPublicKey({key:Buffer.concat([bytes('302a300506032b6570032100'),pub]),format:'der',type:'spki'}),sig);
function manifest(m){exact(m,['version','files']);assert.equal(m.version,'0.10.0');assert(Array.isArray(m.files)&&m.files.length<=4096&&jcs(m).length<=1048576);let last=null;for(const f of m.files){exact(f,['path','sha256']);assert(typeof f.path==='string'&&Buffer.byteLength(f.path)<=1024&&!/[\\\x00]/.test(f.path));assert(f.path.split('/').every(p=>p!==''&&p!=='.'&&p!=='..'));if(last!==null)assert(Buffer.compare(Buffer.from(last),Buffer.from(f.path))<0);last=f.path;hex(f.sha256);}}
function policy(p){exact(p,['version','issuer','epoch','engine','artifacts']);assert.equal(p.version,'0.10.0');uuid(p.epoch);assert(/^did:sage:web:[a-z0-9.-]+:[A-Za-z0-9._-]+$/.test(p.issuer));assert(/^[\x00-\x7f]{1,128}$/.test(p.engine));manifest(p.artifacts);bounds(p);assert(p.artifacts.files.length>0&&jcs(p).length<=1048576);return sha(Buffer.concat([Buffer.from('sage-policy|0.10.0\0'),jcs(p)]));}
function bounds(x){let members=0;function walk(v,d){if(v&&typeof v==='object'){assert(d<=32);if(!Array.isArray(v))members+=Object.keys(v).length;for(const z of Object.values(v))walk(z,d+1);}}walk(x,1);assert(members<=4096&&jcs(x).length<=1048576);}
function envelope(raw,kind,pub){assert(raw.length<=1048576);const e=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));exact(e,[kind,'proof']);bounds(e);assert(verify(bytes(pub),Buffer.concat([Buffer.from(kind==='intent'?'sage-execution-intent|0.10.0\0':'sage-tool-result|0.10.0\0'),jcs(e[kind])]),decode(e.proof)));return e;}
function time(t,x){assert(x.clock_trusted&&Number.isSafeInteger(t.created)&&Number.isSafeInteger(t.expires)&&t.created>=0&&t.expires>t.created&&t.expires-t.created<=300&&t.created<=x.now+30&&x.now<t.expires);}
function intent(x){const e=envelope(bytes(x.envelope_hex),'intent',x.public_key_hex),i=e.intent;exact(i,['version','profile','request_id','call_id','parent_call_id','original_digest','issuer','recipient','tool','arguments','policy_digest','manifest_digest','created','expires','nonce','keyid','alg']);assert.equal(i.version,'0.10.0');assert.equal(i.profile,'sage-execution-guard');uuid(i.request_id);uuid(i.call_id);if(i.parent_call_id!==null)uuid(i.parent_call_id);for(const k of ['original_digest','policy_digest','manifest_digest'])hex(i[k]);assert.equal(decode(i.nonce).length,16);assert.equal(i.nonce.length,22);time(i,x);assert(x.active_key&&x.policy_allow);assert.equal(i.issuer,x.expected_issuer);assert.equal(i.recipient,x.expected_recipient);assert.equal(i.keyid,i.issuer+'#signing-1');assert.equal(i.alg,'ed25519');assert.equal(i.original_digest,x.original_digest);assert.equal(i.policy_digest,policy(x.approved_policy));assert.equal(x.approved_policy.issuer,i.issuer);manifest(x.approved_manifest);assert.equal(i.manifest_digest,hash(x.approved_manifest));assert(i.tool!=='sage_secure_call'&&i.tool===x.tool_schema.tool);exact(i.arguments,x.tool_schema.required);for(const [k,t]of Object.entries(x.tool_schema.properties))assert.equal(typeof i.arguments[k],t);}
function result(x){const e=envelope(bytes(x.envelope_hex),'result',x.public_key_hex),r=e.result,i=x.intent_envelope.intent;exact(r,['version','request_id','call_id','issuer','recipient','created','expires','keyid','alg','intent_digest','status','output']);assert.equal(r.version,'0.10.0');time(r,x);assert(x.active_key&&x.outstanding);assert.equal(r.issuer,i.recipient);assert.equal(r.recipient,i.issuer);assert.equal(r.request_id,i.request_id);assert.equal(r.call_id,i.call_id);assert.equal(r.keyid,r.issuer+'#signing-1');assert.equal(r.alg,'ed25519');assert.equal(r.intent_digest,hash(x.intent_envelope));assert(['pending','completed','rejected','unknown'].includes(r.status));assert(r.output&&typeof r.output==='object'&&!Array.isArray(r.output));if(r.status!=='completed')assert.deepEqual(r.output,{});}
const suite=read('guard-records.json');assert.equal(new Set(suite.cases.map(c=>c.id)).size,suite.cases.length);
for(const c of suite.cases){let ok=true,output={valid:true};const x=c.input;
 assert(['sage.guard.json.bounds','sage.guard.original.commit','sage.guard.manifest.verify','sage.guard.policy.commit','sage.guard.intent.verify','sage.guard.result.verify','sage.guard.mcp.result','signature.verify','jcs.canonicalize'].includes(c.operation));
 try{
  switch(c.operation){
   case 'sage.guard.original.commit':{assert(x.items.length<=1024);const items=x.items.map(i=>i.hex!==undefined?bytes(i.hex):Buffer.alloc(i.length,i.byte));assert(items.reduce((s,b)=>s+b.length,0)<=1048576);const count=Buffer.alloc(4);count.writeUInt32BE(items.length);const framed=Buffer.concat([Buffer.from('sage-original|0.10.0\0'),count,...items.flatMap(b=>{new TextDecoder('utf-8',{fatal:true}).decode(b);const len=Buffer.alloc(8);len.writeBigUInt64BE(BigInt(b.length));return[len,b];})]);output={original_digest:sha(framed)};break;}
   case 'sage.guard.json.bounds':{const raw=Buffer.concat([bytes(x.prefix_hex),Buffer.alloc(x.repeat_count,x.repeat_byte),bytes(x.suffix_hex)]);assert(raw.length<=1048576);bounds(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)));break;}
   case 'sage.guard.manifest.verify':manifest(x.manifest);assert.equal(x.artifacts.length,x.manifest.files.length);for(const f of x.manifest.files){const a=x.artifacts.find(a=>a.path===f.path);assert(a);assert.equal(sha(bytes(a.bytes_hex)),f.sha256);}output={manifest_digest:hash(x.manifest)};break;
   case 'sage.guard.policy.commit':output={policy_digest:policy(x.descriptor)};break;
   case 'sage.guard.intent.verify':intent(x);break;
   case 'sage.guard.result.verify':result(x);break;
   case 'sage.guard.mcp.result':assert.equal(x.text,jcs(x.structured).toString());assert(!x.extra_block);assert.equal(x.isError,x.structured.result.status!=='completed');break;
   case 'signature.verify':assert(verify(bytes(x.public_key_hex),bytes(x.message_hex),bytes(x.signature_hex)));break;
   case 'jcs.canonicalize':output={canonical_hex:jcs(JSON.parse(bytes(x.document_hex))).toString('hex')};break;
  }
 }catch{ok=false;}
 assert.deepEqual(c.expected,{verdict:ok?'ACCEPT':'REJECT',output:ok?output:{}},c.id);
}
let steps=0;const m=read('guard-manifest.json');assert.equal(m.records_sha256,sha(fs.readFileSync(path.join(root,'guard-records.json'))));
assert.equal(new Set(m.scenarios.map(s=>s.id)).size,37);
for(const entry of m.scenarios){const raw=fs.readFileSync(path.join(root,'guard-scenarios',entry.file));assert.equal(entry.sha256,sha(raw));const f=JSON.parse(raw);assert.equal(f.id,entry.id);const setup=f.steps[0].input;
 let approved=setup.envelope.intent.policy_digest,epochs=new Set([setup.policy.epoch]);let ledger={},nonces=new Set(),outer=new Set(),now=0,intact=true,allowed=true,measured=true,clock=true,signer=true,argumentsList=[],instances=[],terminal=null,lastPoll=null,outstanding=new Set(['a','b','c','d']);
 let effects={reservations:0,dispatch:0,responses:0,result_signatures:0,consumed:0,polls:0};
 function apply(a,stepIndex){let ok=true,out={};const k=a.action;
  if(k==='clock'){now=a.elapsed;return[true,{}];}
  if(k==='retire')allowed=false;
  else if(k==='measure')measured=a.same_immutable_instance;
  else if(k==='clock-trust')clock=a.trusted;
  else if(k==='signer')signer=a.available;
  else if(k==='gate-failure')allowed=false;
  else if(k==='peer-provision')return[false,{}];
  else if(k==='recover'){if(!a.trusted_admin||!a.scope_synchronized||!a.old_commitments_retired||!a.new_mapping_durable||epochs.has(a.descriptor.epoch))return[false,{}];epochs.add(a.descriptor.epoch);approved=policy(a.descriptor);intact=true;allowed=true;}
  else if(k==='client-new-call')return[a.reason!=='retry-unknown',{}];
  else if(k==='lose-ledger'){intact=false;ledger={};}
  else if(k==='crash'){for(const e of Object.values(ledger))if(['RESERVED','EXECUTING'].includes(e.state)){e.state='UNKNOWN';e.terminal=null;}}
  else if(k==='client-poll'){if(terminal||now>=300||(lastPoll!==null&&now-lastPoll<1))return[false,{}];lastPoll=now;effects.polls++;}
  else if(k==='client-result'){if(!outstanding.has(a.invocation)||a.verified===false)return[false,{}];outstanding.delete(a.invocation);const s=a.envelope.result.status;if(s==='pending')return[true,{disposition:terminal?'ignored':'pending'}];if(terminal)return hash(a.envelope)===terminal?[true,{disposition:'ignored'}]:[false,{}];terminal=hash(a.envelope);effects.consumed++;return[true,{disposition:'consumed'}];}
  else{
   const env=a.envelope||setup.envelope,i=env.intent,cid=i.call_id;let e=ledger[cid];
   if(k==='submit'||k==='reject'){
    const invocation=a.invocation||'invoke-'+stepIndex;if(outer.has(invocation))return[false,{}];outer.add(invocation);
    if(!intact||!clock||!allowed||!measured||now>=300||a.verified===false||i.policy_digest!==approved)return[false,{}];
    if(e){if(k==='reject'||e.digest!==hash(env))return[false,{}];}
    else{if(nonces.has(i.nonce))return[false,{}];nonces.add(i.nonce);effects.reservations++;e={state:k==='reject'?'REJECTED':'RESERVED',digest:hash(env),arguments:i.arguments,terminal:null};ledger[cid]=e;}
    const status=['COMPLETED','REJECTED','UNKNOWN'].includes(e.state)?e.state.toLowerCase():'pending';if(!signer)return[false,{}];if(status==='pending')effects.result_signatures++;else if(e.terminal===null){e.terminal=hash(setup.signer_fixtures[status]);effects.result_signatures++;}effects.responses++;return[true,{status}];
   }
   if(k==='dispatch'){if(!e||e.state!=='RESERVED')return[false,{}];if(!intact||!allowed||!measured||!clock||now>=300){e.state='REJECTED';return[false,{}];}e.state='EXECUTING';effects.dispatch++;argumentsList.push(e.arguments);instances.push('artifact-A');}
   else if(k==='complete'){if(!e||e.state!=='EXECUTING'||!signer||a.persistence_failure)return[false,{}];e.state='COMPLETED';e.terminal=hash(setup.signer_fixtures.completed);effects.result_signatures++;}
   else throw Error('unknown action '+k);
  }return[ok,out];
 }
 for(let n=0;n<f.steps.length;n++){const s=f.steps[n];let ok=true,out={};
  if(n===0){assert.equal(s.operation,'control.guard.setup');manifest(setup.manifest);policy(setup.policy);
   for(const env of [setup.envelope,setup.recovery_envelope])assert(verify(bytes(setup.issuer_public_key_hex),Buffer.concat([Buffer.from('sage-execution-intent|0.10.0\0'),jcs(env.intent)]),decode(env.proof)));
   assert.equal(setup.recovery_envelope.intent.policy_digest,policy(setup.recovery_policy));
   for(const group of [setup.signer_fixtures,setup.recovery_signer_fixtures])for(const env of Object.values(group))assert(verify(bytes(setup.executor_public_key_hex),Buffer.concat([Buffer.from('sage-tool-result|0.10.0\0'),jcs(env.result)]),decode(env.proof)));
  }
  else if(s.input.action==='inspect')out={entries:ledger,ledger_intact:intact,policy_active:allowed,measured,clock_trusted:clock,approved_policy:approved,dispatch_arguments:argumentsList,dispatch_instances:instances,client_terminal:terminal};
  else if(s.operation==='subject.parallel'){assert.equal(s.input.barrier,'before-protected-commit');out={verdicts:s.input.gate_order.map(a=>apply(a,n)[0]?'ACCEPT':'REJECT')};}
  else [ok,out]=apply(s.input,n);
  assert.deepEqual(s.expected,{verdict:ok?'ACCEPT':'REJECT',output:ok?out:{}},entry.id+':'+s.id);assert.deepEqual(s.effects,effects,entry.id+':'+s.id+' effects');steps++;
 }
}
assert.equal(suite.cases.length,102);assert.equal(steps,297);
console.log(`${suite.cases.length} Guard cases and ${m.scenarios.length} scenarios (${steps} steps) independently audited; no runtime/host certification.`);
