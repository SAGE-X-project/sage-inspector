"""Mechanism projections of full boundary fixtures; never whole-envelope verdicts."""
import base64
import hashlib
import json
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
suite=json.loads((root/'vectors/0.10.0/http-boundaries.json').read_text())
cases=[]
def canonical(o):
    return json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
selected=['valid-request','valid-response','valid-whitespace-body','valid-response-canonical-request-hash',
          'wrong-request-hash','hash-without-signature','payload-only-hash','stale-hash-with-valid-outer-binding',
          'request-inner-signature','request-payload-tamper','response-inner-signature']
for c in suite['cases']:
    if c['id'] not in selected:
        continue
    response=bool(c['input']['response_hex'])
    raw=bytes.fromhex(c['input']['response_hex'] if response else c['input']['request_hex'])
    body=raw.split(b'\r\n\r\n',1)[1]
    o=json.loads(body)
    complete=canonical(o)
    cases.append(dict(id=c['id']+'-jcs',operation='jcs.canonicalize',rule_ids=['TRANSPORT-03' if response else 'TRANSPORT-02'],source_ids=['sage-transport'],
                      derivation='Canonical signed envelope bytes from the fixed boundary case; restricted ASCII/integer JCS subset cross-checked with ECMAScript.',
                      input={'document_hex':body.hex()},expected={'verdict':'ACCEPT','output':{'canonical_hex':complete.hex()}}))
    sig=o.pop('signature')
    domain=b'sage-wire-response|0.10.0\n' if response else b'sage-wire-request|0.10.0\n'
    invalid=c['id'] in ['request-inner-signature','request-payload-tamper','response-inner-signature']
    cases.append(dict(id=c['id']+'-inner-signature',operation='signature.verify',rule_ids=['TRANSPORT-03' if response else 'TRANSPORT-02'],source_ids=['sage-transport'],
                      derivation='Inner domain-separated signature only. A valid signature does not establish response request-hash, freshness, registry or execution authorization.',
                      input={'algorithm':'ed25519','public_key_hex':c['input']['public_key_hex'],'message_hex':(domain+canonical(o)).hex(),'signature_hex':base64.urlsafe_b64decode(sig+'==').hex()},
                      expected={'verdict':'REJECT' if invalid else 'ACCEPT','output':{} if invalid else {'valid':True}}))
    # Domain substitution must not verify even for a valid signed message.
    if c['id'] in ['valid-request','valid-response']:
        inverse=b'sage-wire-request|0.10.0\n' if response else b'sage-wire-response|0.10.0\n'
        item=json.loads(json.dumps(cases[-1]))
        item['id']=c['id']+'-wrong-domain'
        item['input']['message_hex']=(inverse+canonical(o)).hex()
        item['expected']={'verdict':'REJECT','output':{}}
        cases.append(item)
suite.update(id='sage-http-envelope-primitives-0.10.0',cases=cases)
out=Path(sys.argv[1]) if len(sys.argv)>1 else root/'vectors/0.10.0/http-envelope-primitives.json'
out.write_text(json.dumps(suite,indent=2)+'\n')
print(len(cases),'envelope primitive projections',out)
