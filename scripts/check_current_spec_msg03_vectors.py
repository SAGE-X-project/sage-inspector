"""Verify signed response bases bind the retained request Signature field."""

import base64
import hashlib
import json

from current_spec_catalog import ROOT, load, require
from check_current_spec_msg01_vectors import verify_signature
from check_current_spec_msg02_vectors import base_and_signature


IDS = ('MSG-03-P', 'MSG-03-N01', 'MSG-03-N02', 'MSG-03-N03', 'MSG-03-N04')
CLIENT = 'did:sage:web:agent.example:alice'
SERVER = 'did:sage:web:agent.example:bob'
OTHER = 'did:sage:web:agent.example:mallory'
URL = 'https://agent.example/call?x=1'
RESPONSE_COVERAGE = (
    '@status', '@method;req', '@target-uri;req', '@authority;req',
    'content-digest;req', 'signature;req', 'x-sage-version;req',
    'content-type', 'content-digest', 'x-sage-did', 'x-sage-version')


def parse(raw, response=False):
    head, body = raw.split(b'\r\n\r\n', 1)
    lines = head.decode('ascii').split('\r\n')
    if response:
        require(lines[0] == 'HTTP/1.1 200 OK', 'MSG-03 response status')
    else:
        require(lines[0] == 'POST ' + URL + ' HTTP/1.1', 'MSG-03 request target')
    headers = {}
    for line in lines[1:]:
        name, value = line.split(': ', 1)
        name = name.lower()
        require(name not in headers, 'duplicate MSG-03 header')
        headers[name] = value
    require(headers['content-length'] == str(len(body)), 'MSG-03 framing')
    return headers, body


def response_base(request, response):
    request_headers, request_body = parse(request)
    response_headers, response_body = parse(response, response=True)
    values = {'@status': '200', '@method;req': 'POST',
              '@target-uri;req': URL, '@authority;req': request_headers['host']}
    values.update({name + ';req': request_headers[name] for name in
                   ('content-digest', 'signature', 'x-sage-version')})
    values.update(response_headers)
    member = '(' + ' '.join('"' + name.split(';')[0] + '"' +
                            (';req' if name.endswith(';req') else '')
                            for name in RESPONSE_COVERAGE) + ')'
    params = response_headers['signature-input']
    require(params.startswith('sig1=' + member + ';keyid=') and
            ';alg="ed25519";' in params and
            params.endswith(';tag="sage-0.10.0"'),
            'MSG-03 exact ordered response coverage')
    lines = []
    for name in RESPONSE_COVERAGE:
        label = ('"' + name.split(';')[0] + '"' +
                 (';req' if name.endswith(';req') else ''))
        lines.append(label + ': ' + values[name])
    base = ('\n'.join(lines) + '\n"@signature-params": ' +
            params.removeprefix('sig1=')).encode()
    return base, request_headers, request_body, response_headers, response_body


def signature(headers):
    value = headers['signature']
    require(value.startswith('sig1=:') and value.endswith(':'),
            'MSG-03 signature field')
    return base64.b64decode(value[6:-1], validate=True)


def check(root=ROOT):
    fixtures = {}
    requests = {}
    responses = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime',
                'MSG-03 fixture identity')
        inp = fixture['input']['input']
        require(inp['body_repeat'] == 1, 'MSG-03 body expansion')
        fixtures[ident] = fixture
        requests[ident] = bytes.fromhex(inp['request_hex'])
        responses[ident] = bytes.fromhex(inp['response_hex'])

    control = fixtures['MSG-03-P']
    require(control['input']['operation'] == 'http.msg01.primitives' and
            control['expected']['verdict'] == 'ACCEPT',
            'MSG-03 positive primitive scope')
    base, req_h, req_body, resp_h, resp_body = response_base(
        requests['MSG-03-P'], responses['MSG-03-P'])
    request_control = load((root / 'vectors/0.10.0/current-spec/MSG-02-P.json')
                           .read_bytes())
    require(requests['MSG-03-P'] == bytes.fromhex(
                request_control['input']['input']['request_hex']),
            'MSG-03 retained request differs from verified MSG-02 control')
    request_base, request_signature, _ = base_and_signature(requests['MSG-03-P'])
    verify_signature(bytes.fromhex(
        request_control['input']['input']['public_key_hex']),
        request_signature, request_base)
    req_doc, resp_doc = json.loads(req_body), json.loads(resp_body)
    require(req_h['x-sage-did'] == req_doc['did'] == CLIENT and
            req_doc['version'] == '0.10.0' and
            resp_h['x-sage-did'] == resp_doc['did'] == SERVER and
            resp_doc['recipient'] == CLIENT and resp_doc['success'] is True and
            resp_h['x-sage-version'] == resp_doc['version'] == '0.10.0' and
            ';keyid="' + SERVER + '#signing-1";' in resp_h['signature-input'] and
            resp_h['content-digest'] == 'sha-256=:' +
            base64.b64encode(hashlib.sha256(resp_body).digest()).decode() + ':' and
            control['expected']['output'] == {'base_hex': base.hex(),
                                               'digest_valid': True},
            'MSG-03 response signer and content binding')
    server_public = bytes.fromhex(control['input']['input']['public_key_hex'])
    verify_signature(server_public, signature(resp_h), base)

    for ident in IDS[1:]:
        fixture = fixtures[ident]
        inp = fixture['input']['input']
        require(fixture['expected']['verdict'] == 'REJECT' and
                fixture['expected']['output'] == {} and
                inp['body_repeat'] == 1, 'MSG-03 negative verdict')
        if fixture['input']['operation'] == 'sage.http.verify':
            require(inp['expected_response_did'] == SERVER and
                    inp['trusted_now_unix'] == 1700000010,
                    'MSG-03 trusted peer context')
        else:
            require(set(inp) == {'request_hex', 'response_hex',
                                 'public_key_hex', 'body_repeat'},
                    'MSG-03 primitive input')
        if ident == 'MSG-03-N01':
            original_sig = req_h['signature']
            replaced = 'sig1=:' + base64.b64encode(bytes(64)).decode() + ':'
            require(fixture['input']['operation'] == 'sage.http.verify' and
                    requests[ident] == requests['MSG-03-P'].replace(
                        ('Signature: ' + original_sig + '\r\n').encode(),
                        ('Signature: ' + replaced + '\r\n').encode(), 1) and
                    responses[ident] == responses['MSG-03-P'] and
                    inp['public_key_hex'] == server_public.hex(),
                    'MSG-03 altered retained request Signature')
            changed_base, *_ = response_base(requests[ident], responses[ident])
            require(changed_base != base, 'MSG-03 request Signature was not bound')
            try:
                verify_signature(server_public, signature(resp_h), changed_base)
            except ValueError:
                pass
            else:
                raise ValueError('response signature accepted changed request')
        elif ident == 'MSG-03-N02':
            require(fixture['input']['operation'] == 'rfc9421.base' and
                    requests[ident] == b'' and
                    responses[ident] == responses['MSG-03-P'],
                    'MSG-03 missing original request context')
        elif ident == 'MSG-03-N03':
            require(fixture['input']['operation'] == 'sage.http.verify' and
                    requests[ident] == requests['MSG-03-P'],
                    'MSG-03 wrong peer request context')
            other_base, _, _, other_h, other_body = response_base(
                requests[ident], responses[ident])
            require(other_h['x-sage-did'] == json.loads(other_body)['did'] == OTHER and
                    ';keyid="' + OTHER + '#signing-1";' in
                    other_h['signature-input'] and
                    other_h['content-digest'] == 'sha-256=:' +
                    base64.b64encode(hashlib.sha256(other_body).digest()).decode()
                    + ':' and
                    all(other_h[name] == resp_h[name] for name in
                        ('content-type', 'x-sage-version')),
                    'MSG-03 independently signed wrong peer')
            verify_signature(bytes.fromhex(inp['public_key_hex']),
                             signature(other_h), other_base)
        else:
            head, body = responses['MSG-03-P'].split(b'\r\n\r\n', 1)
            unsigned = b'\r\n'.join(line for line in head.split(b'\r\n')
                                    if not line.startswith(
                                        (b'Signature-Input: ', b'Signature: ')))
            require(fixture['input']['operation'] == 'rfc9421.base' and
                    requests[ident] == requests['MSG-03-P'] and
                    responses[ident] == unsigned + b'\r\n\r\n' + body and
                    json.loads(body)['success'] is True,
                    'MSG-03 unsigned success response')
    return len(IDS)


if __name__ == '__main__':
    print('Verified MSG-03 fixtures:', check())
