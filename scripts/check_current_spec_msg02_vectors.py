"""Verify MSG-02 HTTP bindings and isolate five receiver-side conditions."""

import base64
import hashlib
import json

from current_spec_catalog import ROOT, load, require
from check_current_spec_msg01_vectors import COVERED, verify_signature


IDS = ('MSG-02-P', 'MSG-02-N01', 'MSG-02-N02', 'MSG-02-N03',
       'MSG-02-N04', 'MSG-02-N05')
ENDPOINT = 'https://agent.example/call?x=1'
DID = 'did:sage:web:agent.example:alice'


def inspect(raw):
    head, body = raw.split(b'\r\n\r\n', 1)
    lines = head.decode('ascii').split('\r\n')
    method, target, version = lines[0].split(' ')
    require(method == 'POST' and version == 'HTTP/1.1', 'MSG-02 request line')
    headers = {}
    for line in lines[1:]:
        name, value = line.split(': ', 1)
        name = name.lower()
        require(name not in headers, 'duplicate MSG-02 header')
        headers[name] = value
    require(headers['content-length'] == str(len(body)), 'MSG-02 framing')
    return target, headers, body


def base_and_signature(raw):
    target, headers, body = inspect(raw)
    require(headers['signature-input'].startswith('sig1=(' +
            ' '.join('"' + name + '"' for name in COVERED) + ')'),
            'MSG-02 ordered coverage')
    values = {'@method': 'POST', '@target-uri': target,
              '@authority': headers['host']}
    values.update(headers)
    base = ('\n'.join('"' + name + '": ' + values[name] for name in COVERED) +
            '\n"@signature-params": ' +
            headers['signature-input'].removeprefix('sig1=')).encode()
    sig = headers['signature'].removeprefix('sig1=:').removesuffix(':')
    require(headers['signature'] == 'sig1=:' + sig + ':',
            'MSG-02 sig1 encoding')
    return base, base64.b64decode(sig, validate=True), body


def check(root=ROOT):
    fixtures = {}
    wires = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime',
                'MSG-02 fixture identity')
        inp = fixture['input']['input']
        require(inp['response_hex'] == '' and inp['body_repeat'] == 1,
                'MSG-02 request-only input')
        fixtures[ident] = fixture
        wires[ident] = bytes.fromhex(inp['request_hex'])

    control = wires['MSG-02-P']
    positive = fixtures['MSG-02-P']
    require(positive['input']['operation'] == 'http.msg01.primitives' and
            positive['expected']['verdict'] == 'ACCEPT',
            'MSG-02 positive primitive scope')
    target, headers, body = inspect(control)
    document = json.loads(body)
    require(target == ENDPOINT and headers['host'] == 'agent.example' and
            headers['content-type'] == 'application/json' and
            headers['x-sage-did'] == document['did'] == DID and
            headers['x-sage-version'] == document['version'] == '0.10.0' and
            headers['content-digest'] == 'sha-256=:' +
            base64.b64encode(hashlib.sha256(body).digest()).decode() + ':' and
            body == json.dumps(document, sort_keys=True,
                               separators=(',', ':')).encode() and
            ';keyid="' + DID + '#signing-1";' in headers['signature-input'],
            'MSG-02 body/header/endpoint binding')
    base, signature, _ = base_and_signature(control)
    require(positive['expected']['output'] == {'base_hex': base.hex(),
                                                'digest_valid': True},
            'MSG-02 expected base and digest')
    public = bytes.fromhex(positive['input']['input']['public_key_hex'])
    verify_signature(public, signature, base)

    for ident in IDS[1:]:
        fixture = fixtures[ident]
        inp = fixture['input']['input']
        require(inp['public_key_hex'] == public.hex() and
                fixture['expected']['verdict'] == 'REJECT' and
                fixture['expected']['output'] == {},
                'MSG-02 negative trusted key and verdict')
        operation = fixture['input']['operation']
        raw = wires[ident]
        if operation == 'sage.http.verify':
            require(inp['receiver_endpoint'] == {'target_uri': ENDPOINT,
                                                   'authority': 'agent.example'} and
                    inp['trusted_now_unix'] == 1700000010,
                    'MSG-02 trusted receiver context')
        else:
            require(set(inp) == {'request_hex', 'response_hex',
                                 'public_key_hex', 'body_repeat'},
                    'MSG-02 primitive context')
        if ident == 'MSG-02-N01':
            require(operation == 'sage.http.verify' and
                    raw == control.replace(b'POST https://agent.example/call?x=1 ',
                                           b'POST https://agent.example/other?x=1 ', 1),
                    'MSG-02 signed target mutation')
        elif ident == 'MSG-02-N02':
            candidate_target, candidate_headers, candidate_body = inspect(raw)
            require(operation == 'sage.http.verify' and
                    candidate_target == 'https://attacker.example/call?x=1' and
                    candidate_headers['host'] == 'attacker.example' and
                    candidate_headers['forwarded'] ==
                    'host=agent.example;proto=https' and
                    candidate_headers['x-forwarded-host'] == 'agent.example' and
                    candidate_body == body and
                    all(candidate_headers[name] == headers[name] for name in
                        ('content-type', 'content-digest', 'x-sage-did',
                         'x-sage-version', 'signature-input')),
                    'MSG-02 forwarded endpoint spoof')
            attack_base, attack_signature, _ = base_and_signature(raw)
            verify_signature(public, attack_signature, attack_base)
        elif ident == 'MSG-02-N03':
            require(operation == 'sage.content-digest' and
                    raw == control.replace(b'Content-Length: ' +
                    str(len(body)).encode(), b'Content-Length: ' +
                    str(len(body) + 1).encode(), 1) + b' ' and
                    json.loads(body + b' ') == document,
                    'MSG-02 unsigned body whitespace')
        elif ident == 'MSG-02-N04':
            require(operation == 'rfc9421.base' and
                    raw == control.replace(b'X-Sage-Version: 0.10.0\r\n',
                                           b'', 1),
                    'MSG-02 missing covered version')
        else:
            unknown_target, unknown_headers, unknown_body = inspect(raw)
            require(operation == 'sage.http.verify' and
                    unknown_target == target and
                    unknown_headers['host'] == headers['host'] and
                    unknown_headers['x-sage-version'] == '0.9.0' and
                    json.loads(unknown_body) == {'did': DID, 'version': '0.9.0'}
                    and unknown_headers['content-digest'] == 'sha-256=:' +
                    base64.b64encode(hashlib.sha256(unknown_body).digest()).decode()
                    + ':' and
                    all(unknown_headers[name] == headers[name] for name in
                        ('content-type', 'x-sage-did', 'signature-input')),
                    'MSG-02 unknown but internally matching version')
            unknown_base, unknown_signature, _ = base_and_signature(raw)
            verify_signature(public, unknown_signature, unknown_base)
    return len(IDS)


if __name__ == '__main__':
    print('Verified MSG-02 fixtures:', check())
