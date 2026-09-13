// Independent ECMAScript serialization check for the positive JCS literals.
// Negative SAGE parsing cases are specified separately; JSON.parse loses duplicates.
const fs = require('node:fs');
const suite = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}
let count = 0;
for (const c of suite.cases) {
  if (c.operation !== 'jcs.canonicalize' || c.expected.verdict !== 'ACCEPT') continue;
  const actual = Buffer.from(canonical(JSON.parse(Buffer.from(c.input.document_hex, 'hex').toString('utf8')))).toString('hex');
  if (actual !== c.expected.output.canonical_hex) throw new Error('Expected literal differs: ' + c.id);
  count++;
}
if (count === 0) throw new Error('No positive JCS fixtures');
console.log(`${count} positive JCS literals agree with ECMAScript serialization`);
