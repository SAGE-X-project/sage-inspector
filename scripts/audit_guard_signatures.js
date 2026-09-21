// Independent Node/OpenSSL audit of public fixtures generated with Python cryptography.
const fs = require('node:fs');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const allRows = JSON.parse(fs.readFileSync(process.argv[2])).cases;
assert(allRows.every(c=>['ed25519','p256','secp256k1'].includes(c.audit.algorithm)));
const rows = allRows.filter(c=>c.audit.algorithm!=='secp256k1');
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k)+':'+canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
for (const c of rows) {
  const envelope = JSON.parse(Buffer.from(c.input.envelope_hex, 'hex').toString('utf8'));
  const role = c.operation === 'sage.guard.intent.verify' ? 'intent' : 'result';
  const domain = role === 'intent' ? 'sage-execution-intent|0.10.0' : 'sage-tool-result|0.10.0';
  const message = Buffer.from(domain+'\0'+canonical(envelope[role]));
  assert.equal(message.toString('hex'), c.audit.message_hex);
  const signature = Buffer.from(envelope.proof, 'base64url');
  assert.equal(signature.toString('hex'), c.audit.signature_hex);
  const key = crypto.createPublicKey({key:Buffer.from(c.audit.spki_hex,'hex'),format:'der',type:'spki'});
  const jwk = key.export({format:'jwk'});
  const raw = c.audit.algorithm === 'ed25519' ? Buffer.from(jwk.x,'base64url') : Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]);
  assert.equal(raw.toString('hex'),c.input.public_key_hex);
  if (process.argv.includes('--low-s') && c.audit.algorithm === 'p256') {
    const n=BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
    assert.equal(signature.length,64);
    const r=BigInt('0x'+signature.subarray(0,32).toString('hex'));
    const s=BigInt('0x'+signature.subarray(32).toString('hex'));
    assert(r>0n && r<n && s>0n && s<=n/2n,'P-256 scalar range/low-S');
  }
  const valid = crypto.verify(c.audit.algorithm === 'ed25519' ? null : 'sha256', message,
    c.audit.algorithm === 'ed25519' ? key : {key,dsaEncoding:'ieee-p1363'}, signature);
  assert.equal(valid,c.audit.cryptographically_valid,c.id);
}
console.log(JSON.stringify({cases:rows.length,valid:rows.filter(c=>c.audit.cryptographically_valid).length,invalid:rows.filter(c=>!c.audit.cryptographically_valid).length}));
