'use strict';
// Independent Node/OpenSSL oracle for the bounded public result fixture subset.
const fs = require('fs');
const crypto = require('crypto');
function jcs(v) {
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  if (v !== null && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k)+':'+jcs(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
function check(c, publicKey) {
  const raw=Buffer.from(c.envelope_hex,'hex'), intent=Buffer.from(c.intent_hex,'hex');
  const e=JSON.parse(raw), i=JSON.parse(intent).intent;
  const result={version:'0.10.0',request_id:i.request_id,call_id:i.call_id,issuer:i.recipient,recipient:i.issuer,created:c.created,expires:c.created+300,keyid:i.recipient+'#signing-1',alg:'ed25519',intent_digest:crypto.createHash('sha256').update(intent).digest('hex'),status:c.status,output:c.output};
  if(jcs(e)!==raw.toString('utf8')||jcs(e.result)!==jcs(result)||Object.keys(e).sort().join(',')!=='proof,result') throw Error('canonical result or binding mismatch');
  if(typeof e.proof!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(e.proof)) throw Error('proof encoding');
  const proof=Buffer.from(e.proof,'base64url');
  if(proof.length!==64||proof.toString('base64url')!==e.proof) throw Error('proof length');
  const key=crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(publicKey,'hex')]),format:'der',type:'spki'});
  if(!crypto.verify(null,Buffer.concat([Buffer.from('sage-tool-result|0.10.0\0'),Buffer.from(jcs(result))]),key,proof)) throw Error('invalid result proof');
}
module.exports={jcs,check};
if(require.main===module){
 const input=JSON.parse(fs.readFileSync(0,'utf8'));
 if(!Array.isArray(input.cases)||input.cases.length===0) throw Error('missing audit cases');
 input.cases.forEach(c=>check(c,input.public_key_hex));
 console.log(JSON.stringify({status:'PASS',checks:input.cases.length}));
}
