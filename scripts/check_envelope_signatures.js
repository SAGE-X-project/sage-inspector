// Independent verification of inner signature projections, including wrong domains.
const fs = require('node:fs');
const crypto = require('node:crypto');
const suite=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
let count=0;
for (const c of suite.cases) {
  if (c.operation !== 'signature.verify') continue;
  const i=c.input;
  const key=Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(i.public_key_hex,'hex')]);
  const valid=crypto.verify(null,Buffer.from(i.message_hex,'hex'),{key,format:'der',type:'spki'},Buffer.from(i.signature_hex,'hex'));
  if ((valid ? 'ACCEPT' : 'REJECT') !== c.expected.verdict) throw new Error(c.id);
  count++;
}
if (!count) throw new Error('No signatures audited');
console.log(`${count} inner signature projections independently verified`);
