// Independent fixture audit using ECMAScript and Node/OpenSSL, never a core adapter.
// Deliberately restricted to the fixed Ed25519/plain HTTP fixture grammar.
const fs = require('node:fs');
const crypto = require('node:crypto');
function fail(reason) { throw new Error(reason); }
function canonical(x) {
  if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
  if (x !== null && typeof x === 'object') return '{' + Object.keys(x).sort().map(k => JSON.stringify(k) + ':' + canonical(x[k])).join(',') + '}';
  return JSON.stringify(x);
}
function sha(x) { return crypto.createHash('sha256').update(x).digest(); }
function binary(s, length) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) fail('schema');
  const b = Buffer.from(s, 'base64url');
  if (b.toString('base64url') !== s || (length !== undefined && b.length !== length)) fail('schema');
  return b;
}
function verify(key, bytes, signature, reason) {
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(key, 'hex')]);
  if (!crypto.verify(null, Buffer.from(bytes), {key:der,format:'der',type:'spki'}, signature)) fail(reason);
}
function parse(hex) {
  if (!hex) return null;
  const raw = Buffer.from(hex, 'hex');
  const at = raw.indexOf('\r\n\r\n');
  if (at < 0) fail('framing');
  const lines = raw.subarray(0,at).toString('ascii').split('\r\n');
  const first = lines.shift();
  const h = {};
  if (Buffer.byteLength(lines.join('\r\n')+'\r\n') > 32768) fail('fields-size');
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon < 1) fail('framing');
    const name = line.slice(0,colon).toLowerCase();
    if (Object.hasOwn(h,name)) fail(name === 'content-length' ? 'framing' : 'duplicate');
    const value = line.slice(colon+2); // Fixture convention: exactly one separator SP.
    if (['signature','signature-input'].includes(name) && value.length > 8192) fail('signature-size');
    h[name] = value.trim();
  }
  const body = raw.subarray(at+4);
  if (h['transfer-encoding'] || !/^\d+$/.test(h['content-length']) || Number(h['content-length']) !== body.length) fail('framing');
  if (body.length > 16777216) fail('body-size');
  if (h['content-encoding'] || h.trailer || h['content-type'] !== 'application/json') fail('profile');
  return {first,h,body};
}
function outer(m, request, i) {
  const {h,first,body} = m;
  if (!h['signature-input'] || !h.signature) fail('signature-fields');
  const match = /^sig1=(\([^)]*\));(.*)$/.exec(h['signature-input']);
  if (!match) fail('parameters');
  const components = match[1].slice(1,-1).split(' ');
  const params = {};
  for (const part of match[2].split(';')) {
    const index = part.indexOf('=');
    const k = part.slice(0,index), v=part.slice(index+1);
    if (Object.hasOwn(params,k)) fail('parameters');
    params[k] = v;
  }
  if (Object.keys(params).sort().join(',') !== 'alg,created,expires,keyid,nonce,tag' || params.tag !== '"sage-0.10.0"' || params.alg !== '"ed25519"') fail('parameters');
  if (![params.created,params.expires].every(x=>/^\d+$/.test(x) && Number.isSafeInteger(Number(x)))) fail('timestamp');
  const c=Number(params.created), e=Number(params.expires);
  if (e-c <= 0 || e-c > 300) fail('lifetime');
  if (!i.clock_trusted) fail('clock');
  if (c > i.now_unix+30 || i.now_unix >= e+30) fail('freshness');
  const isResponse = first.startsWith('HTTP/');
  const requestComponents = ['"@method"','"@target-uri"','"@authority"','"content-type"','"content-digest"','"x-sage-did"','"x-sage-version"'];
  const responseComponents = ['"@status"', ...['"@method"','"@target-uri"','"@authority"','"content-digest"','"signature"','"x-sage-version"'].map(x=>x+';req'), ...requestComponents.slice(3)];
  if (JSON.stringify(components) !== JSON.stringify(isResponse ? responseComponents : requestComponents)) fail('coverage');
  if (!isResponse && (first.split(' ')[1] !== i.expected_target || h.host !== new URL(i.expected_target).host)) fail('authority');
  const digest = 'sha-256=:'+sha(body).toString('base64')+':';
  if (h['content-digest'] !== digest) fail('digest');
  const lines = components.map(component => {
    const source = component.endsWith(';req') ? request : m;
    if (!source) fail('request-context');
    const name = component.split('"')[1];
    let value;
    if (name === '@method') value=source.first.split(' ')[0];
    else if (name === '@target-uri') value=source.first.split(' ')[1];
    else if (name === '@authority') value=new URL(source.first.split(' ')[1]).host;
    else if (name === '@status') value=source.first.split(' ')[1];
    else value=source.h[name];
    return component+': '+value;
  });
  const base=lines.join('\n')+'\n"@signature-params": '+h['signature-input'].slice(5);
  const s=/^sig1=:([A-Za-z0-9+/]+={0,2}):$/.exec(h.signature);
  if (!s || Buffer.from(s[1],'base64').toString('base64') !== s[1]) fail('signature-fields');
  const kid=JSON.parse(params.keyid);
  if (!Object.hasOwn(i.trusted_keys,kid)) fail('key');
  verify(i.trusted_keys[kid],base,Buffer.from(s[1],'base64'),'outer-signature');
  return {kid,created:c,expires:e,nonce:JSON.parse(params.nonce)};
}
function inner(m, p, i, sent) {
  const o=JSON.parse(m.body.toString('utf8'));
  const response=sent !== undefined;
  const common=['version','id','did','recipient','kid','created','expires','nonce','encoding','signature'];
  const optional=['context_id','task_id','metadata','role'];
  const extra=response ? ['message_id','request_hash','success','data'] : ['payload'];
  const allowed=[...common,...optional,...extra,...(response ? ['error'] : [])];
  if ([...common,...extra].some(k=>!Object.hasOwn(o,k)) || Object.keys(o).some(k=>!allowed.includes(k))) fail('schema');
  const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  if (!uuid.test(o.id) || ['context_id','task_id'].some(k=>Object.hasOwn(o,k) && (typeof o[k] !== 'string' || !uuid.test(o[k])))) fail('schema');
  if (o.version !== '0.10.0' || o.encoding !== 'plain') fail('schema');
  binary(o.nonce,16); binary(response ? o.data : o.payload);
  if (response && (typeof o.success !== 'boolean' || (o.success && Object.hasOwn(o,'error')) || (!o.success && !['authentication_failed','policy_denied','operation_failed','unavailable'].includes(o.error)))) fail('schema');
  const projection={'x-sage-did':'did','x-sage-version':'version','x-sage-message-id':'id','x-sage-context-id':'context_id','x-sage-task-id':'task_id'};
  if (Object.entries(projection).some(([h,k])=>Object.hasOwn(m.h,h) && m.h[h] !== o[k]) || o.kid !== p.kid || o.created !== p.created || o.expires !== p.expires || o.nonce !== p.nonce || o.kid.split('#')[0] !== o.did) fail('projection');
  const unsigned={...o}; delete unsigned.signature;
  if (!Object.hasOwn(i.trusted_keys,o.kid)) fail('key');
  verify(i.trusted_keys[o.kid],(response ? 'sage-wire-response|0.10.0\n' : 'sage-wire-request|0.10.0\n')+canonical(unsigned),binary(o.signature,64),'inner-signature');
  if (response) {
    if (o.message_id !== sent.id || o.did !== sent.recipient || o.recipient !== sent.did || o.context_id !== sent.context_id || o.task_id !== sent.task_id) fail('response-binding');
    binary(o.request_hash,32);
    if (o.request_hash !== sha(canonical(sent)).toString('base64url')) fail('request-hash');
  } else if (o.recipient !== i.expected_recipient) fail('recipient');
  return o;
}
function expanded(i, field) {
  const raw=Buffer.from(i[field+'_hex'],'hex'), n=i[field+'_padding'] || 0;
  if (!n) return raw;
  if (!Number.isInteger(n) || n<1 || n>16777217 || raw[raw.length-1] !== 32) throw new Error('invalid recipe');
  return Buffer.concat([raw.subarray(0,-1),Buffer.alloc(n,32)]);
}
function check(i) {
  if (!i.request_hex) fail('request-context');
  const req=parse(expanded(i,'request').toString('hex')), res=parse(expanded(i,'response').toString('hex'));
  const sent=inner(req,outer(req,null,i),i);
  if (res) inner(res,outer(res,req,i),i,sent);
}
const suite=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const proofs=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
let positives=0,negatives=0;
for (const c of suite.cases) {
  const proof=proofs[c.id];
  if (!proof) throw new Error('Missing proof '+c.id);
  for (const field of ['request','response']) if (sha(expanded(c.input,field)).toString('hex') !== proof[field+'_sha256']) throw new Error('Wire hash '+c.id);
  let reason=null;
  try { check(c.input); } catch(e) { reason=e.message; }
  if (reason !== proof.reason || (reason ? 'REJECT' : 'ACCEPT') !== c.expected.verdict) throw new Error(c.id+': actual '+reason+', expected '+proof.reason);
  if (reason) negatives++; else positives++;
}
if (Object.keys(proofs).length !== suite.cases.length || !positives || !negatives) throw new Error('Incomplete audit');
console.log(`${positives} positive / ${negatives} negative HTTP-envelope fixtures independently checked; rejection causes match`);
