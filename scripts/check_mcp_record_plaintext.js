// Independent Node implementation of the SAGE 0.10.0 record key schedule and AEAD open.
const crypto = require('node:crypto');
const fs = require('node:fs');

function fail(message) { throw new Error(message); }
function hex(value, size, name) {
  if (typeof value !== 'string' || !Number.isInteger(size) || !/^[0-9a-f]+$/.test(value)
      || value.length !== size * 2)
    fail(`invalid ${name}`);
  return Buffer.from(value, 'hex');
}
function hmac(key, data) { return crypto.createHmac('sha256', key).update(data).digest(); }
function expand(prk, info, size) {
  let previous = Buffer.alloc(0), output = Buffer.alloc(0);
  for (let counter = 1; output.length < size; counter++) {
    previous = hmac(prk, Buffer.concat([previous, info, Buffer.from([counter])]));
    output = Buffer.concat([output, previous]);
  }
  return output.subarray(0, size);
}
function u64(value) {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(value);
  return output;
}
function open(job) {
  if (!job || ![0, 1].includes(job.direction)) fail('invalid direction');
  if (typeof job.wire_hex !== 'string' || job.wire_hex.length % 2
      || typeof job.aad_hex !== 'string' || job.aad_hex.length % 2) fail('invalid record encoding');
  const seed = hex(job.seed_hex, 32, 'seed');
  const th = hex(job.th_hex, 32, 'transcript hash');
  const wire = hex(job.wire_hex, job.wire_hex.length / 2, 'wire');
  const caller = hex(job.aad_hex, job.aad_hex.length / 2, 'caller AAD');
  if (wire.length < 36) fail('short record');
  const sequence = wire.readBigUInt64BE(0);
  const nonce = Buffer.concat([Buffer.alloc(4), u64(sequence)]);
  if (!crypto.timingSafeEqual(nonce, wire.subarray(8, 20))) fail('record nonce');
  const label = job.direction === 0 ? 'c2s' : 's2c';
  const generation = sequence / 256n;
  const info = Buffer.concat([Buffer.from(`sage-${label}-key|0.10.0`), th, u64(generation)]);
  const key = expand(seed, info, 32);
  const length = Buffer.alloc(4); length.writeUInt32BE(caller.length);
  const aad = Buffer.concat([Buffer.from('sage-record|0.10.0'), th,
    Buffer.from([job.direction]), u64(sequence), length, caller]);
  const tag = wire.subarray(wire.length - 16);
  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(wire.subarray(20, -16)), decipher.final()]);
  return {direction: job.direction, sequence: sequence.toString(), plaintext_hex: plaintext.toString('hex')};
}

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
if (!Array.isArray(input) || input.length > 32) fail('invalid job list');
process.stdout.write(JSON.stringify(input.map(open)));
