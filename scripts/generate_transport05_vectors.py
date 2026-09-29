"""Generate fixed HTTP dual-signature fixtures from public test material."""

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
SOURCE = ROOT / 'vectors/0.10.0/http-boundaries.json'
OUTPUT = ROOT / 'vectors/0.10.0/transport05-scenarios.json'
COMPONENTS = ('@method', '@target-uri', '@authority', 'content-type',
              'content-digest', 'x-sage-did', 'x-sage-version')


def split(raw):
    head, body = raw.split(b'\r\n\r\n', 1)
    lines = head.decode('ascii').split('\r\n')
    return lines[0], dict(line.split(': ', 1) for line in lines[1:]), body


def wire(start, headers, body):
    return (start + '\r\n' + ''.join(key + ': ' + value + '\r\n'
            for key, value in headers.items()) + '\r\n').encode() + body


def resign(raw, *, params=None, remove_inner=False, header=None):
    start, headers, body = split(raw)
    if remove_inner:
        envelope = json.loads(body)
        del envelope['signature']
        body = json.dumps(envelope, sort_keys=True, separators=(',', ':')).encode()
        headers['Content-Length'] = str(len(body))
        headers['Content-Digest'] = ('sha-256=:' + base64.b64encode(
            hashlib.sha256(body).digest()).decode() + ':')
    if header is not None:
        headers.update(header)
    signature_input = headers['Signature-Input']
    for old, new in (params or {}).items():
        assert signature_input.count(old) == 1
        signature_input = signature_input.replace(old, new)
    headers['Signature-Input'] = signature_input
    values = {'@method': 'POST', '@target-uri': start.split(' ')[1],
              '@authority': headers['Host']}
    values.update({key.lower(): value for key, value in headers.items()})
    base = ('\n'.join('"' + name + '": ' + values[name]
                      for name in COMPONENTS) +
            '\n"@signature-params": ' + signature_input.removeprefix('sig1='))
    headers['Signature'] = 'sig1=:' + base64.b64encode(KEY.sign(base.encode())).decode() + ':'
    return wire(start, headers, body)


def main():
    source = SOURCE.read_bytes()
    rows = {row['id']: row for row in json.loads(source)['cases']}
    raw = lambda name: bytes.fromhex(rows[name]['input']['request_hex'])
    control = raw('valid-request')
    start, headers, body = split(control)
    missing_outer = dict(headers)
    del missing_outer['Signature']
    variants = [
        ('control', 'TRANSPORT-05-P', control, 'ACCEPT', None),
        ('matching-optional-id', 'TRANSPORT-05-P',
         resign(control, header={'X-Sage-Message-ID': json.loads(body)['id']}),
         'ACCEPT', None),
        ('nonce-mismatch', 'TRANSPORT-05-N01', raw('nonce-body-mismatch'),
         'REJECT', 'nonce'),
        ('created-mismatch', 'TRANSPORT-05-N01',
         resign(control, params={';created=1700000000': ';created=1700000001'}),
         'REJECT', 'created'),
        ('expires-mismatch', 'TRANSPORT-05-N01',
         resign(control, params={';expires=1700000300': ';expires=1700000299'}),
         'REJECT', 'expires'),
        ('keyid-mismatch', 'TRANSPORT-05-N01',
         resign(control, params={
             ';keyid="did:sage:web:agent.example:alice#signing-1"':
             ';keyid="did:sage:web:agent.example:bob#signing-1"'}),
         'REJECT', 'keyid'),
        ('missing-outer', 'TRANSPORT-05-N02', wire(start, missing_outer, body),
         'REJECT', 'outer-signature'),
        ('missing-inner', 'TRANSPORT-05-N02',
         resign(control, remove_inner=True), 'REJECT', 'inner-signature'),
        ('unsigned-id-projection', 'TRANSPORT-05-N03',
         raw('header-x-sage-message-id'), 'REJECT', 'header-id'),
    ]
    document = {
        'schema_version': 1,
        'spec_revision': '5bcf511e604579afa63f434013447f44b6858828',
        'source_sha256': hashlib.sha256(source).hexdigest(),
        'scope': 'fixed local HTTP messages; no request is sent or dispatched',
        'variants': [
            {'name': name, 'case_id': case_id, 'request_hex': message.hex(),
             'expected_verdict': verdict, 'mismatch': reason}
            for name, case_id, message, verdict, reason in variants],
    }
    OUTPUT.write_text(json.dumps(document, indent=2) + '\n')
    print('Generated', len(variants), 'TRANSPORT-05 static HTTP variants')


if __name__ == '__main__':
    main()
