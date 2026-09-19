// Public deterministic fixture keys only; independent of both target cores.
'use strict';
const fs=require('fs'),crypto=require('crypto');
const path=require('path');
const root=path.resolve(__dirname,'..');
const {jcs}=require(root+'/scripts/check_guard_results010.js');
const suite=JSON.parse(fs.readFileSync(root+'/vectors/0.10.0/guard-records.json'));
const input=suite.cases.find(c=>c.id==='intent-valid').input;
const env=Buffer.from(input.envelope_hex,'hex'),i=JSON.parse(env).intent;
const seed=crypto.createHash('sha256').update('public Guard fixture executor').digest();
const key=crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
const publicKey=crypto.createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32).toString('hex');
function signed(status,output={},created=1700000000){const result={version:'0.10.0',request_id:i.request_id,call_id:i.call_id,issuer:i.recipient,recipient:i.issuer,created,expires:created+300,keyid:i.recipient+'#signing-1',alg:'ed25519',intent_digest:crypto.createHash('sha256').update(env).digest('hex'),status,output};const proof=crypto.sign(null,Buffer.concat([Buffer.from('sage-tool-result|0.10.0\0'),Buffer.from(jcs(result))]),key).toString('base64url');return Buffer.from(jcs({result,proof})).toString('hex')}
const results={pending:signed('pending'),completed:signed('completed',{value:'ok'}),rejected:signed('rejected'),unknown:signed('unknown'),conflict:signed('completed',{value:'different'}),late:signed('completed',{value:'late'},1700000301)};
const wrong=JSON.parse(Buffer.from(results.completed,'hex'));wrong.proof='A'.repeat(86);results.invalid=Buffer.from(jcs(wrong)).toString('hex');
const oid=n=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const obs=(extra={})=>({ok:true,id:'',intent_hex:'',status:'',first:false,ignored:false,output_hex:'',handoffs:0,...extra});
const command=(action,args={},expected={})=>({action,...args,expected:obs(expected)});
const begin=(n,ok=true)=>command('begin',{id:oid(n)},ok?{id:oid(n),intent_hex:input.envelope_hex}:{ok:false});
const tick=(ms,mono=ms)=>command('tick',{utc:1700000000000+ms,mono});
const take=(n,result,extra={})=>command('accept',{id:oid(n),result},extra);
const first=(status,out)=>({status,first:true,...(out?{output_hex:Buffer.from(jcs(out)).toString('hex')}:{})});
const denied={ok:false};
let cases=[
 ['poll-boundary',[begin(1),tick(999),begin(2,false),tick(1000),begin(2),take(1,'pending',{status:'pending'}),take(2,'completed',first('completed',{value:'ok'})),begin(3,false),take(2,'completed',denied)]],
 ['late-pending-and-duplicate',[begin(1),tick(1000),begin(2),tick(2000),begin(3),take(2,'completed',first('completed',{value:'ok'})),take(1,'pending',{ignored:true}),take(3,'completed',{ignored:true}),begin(4,false)]],
 ['conflicting-terminal',[begin(1),tick(1000),begin(2),take(1,'completed',first('completed',{value:'ok'})),take(2,'conflict',denied),begin(3,false)]],
 ['invalid-consumes-invocation',[begin(1),take(1,'invalid',denied),take(1,'completed',denied),tick(1000),begin(2),take(2,'completed',first('completed',{value:'ok'}))]],
 ['transport-failure',[begin(1),command('failed',{id:oid(1)}),take(1,'completed',denied),tick(1000),begin(2),take(2,'completed',first('completed',{value:'ok'}))]],
 ['unsolicited',[take(1,'completed',denied),begin(1),take(1,'completed',first('completed',{value:'ok'}))]],
 ['accepted-late',[begin(1),tick(301000),begin(2,false),take(1,'late',first('completed',{value:'late'}))]],
 ['expired-result',[begin(1),tick(300000),take(1,'completed',denied),begin(2,false)]],
 ['utc-jump-not-elapsed',[begin(1),tick(10000,999),begin(2,false),tick(10001,1000),begin(2)]],
 ['utc-stall-not-elapsed',[begin(1),tick(999,10000),begin(2,false),tick(1000,10001),begin(2)]],
 ['reused-outer-id',[begin(1),tick(1000),begin(1,false),begin(2)]],
];
for(const status of ['unknown','rejected'])cases.push([status,[begin(1),take(1,status,first(status)),tick(1000),begin(2,false)]]);
for(const name of ['intent_active','policy_allow'])cases.push([name,[begin(1),command('set',{field:name,value:false}),tick(1000),begin(2,false)]]);
cases.push(['result-revoked',[begin(1),command('set',{field:'result_active',value:false}),take(1,'completed',denied),command('set',{field:'result_active',value:true}),take(1,'completed',denied),tick(1000),begin(2),take(2,'completed',first('completed',{value:'ok'}))]]);
for(const [name,commands] of cases)commands.push(command('close'));
for(const [name,commands] of [
 ['utc-rollback',[begin(1),tick(1000),begin(2),tick(999,1001),begin(3,false)]],
 ['monotonic-rollback',[begin(1),tick(1000),begin(2),tick(1001,999),take(1,'completed',denied)]],
 ['clock-unavailable',[begin(1),command('set',{field:'clock_ok',value:false}),take(1,'completed',denied)]]
]){commands.push(command('close',{},denied));cases.push([name,commands]);}
for(const [,steps] of cases){let count=0;for(const q of steps){if(q.action==='begin'&&q.expected.ok)count++;q.expected.handoffs=count}}
const vector={version:'0.10.0',source:'snapshot/profiles/agent-mcp-security.md EXEC-05 and EXEC-07; independently signed public Node/OpenSSL fixtures; no host certification',input,public_key_hex:publicKey,results,cases:cases.map(([id,steps])=>({id,steps}))};
const target=root+'/vectors/0.10.0/guard-client.json', raw=JSON.stringify(vector,null,2)+'\n';
if(process.argv.includes('--check')){if(fs.readFileSync(target,'utf8')!==raw)throw Error('client fixture drift')}else{fs.writeFileSync(target,raw)}
console.log(cases.length+' independent client cases');
