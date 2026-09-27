"""Audit MSG-06 generic errors and signed failure fixtures independently."""

import base64
import hashlib
import json

from current_spec_catalog import ROOT, load, require
from check_current_spec_msg01_vectors import verify_signature
from check_current_spec_msg02_vectors import base_and_signature
from check_current_spec_msg03_vectors import response_base, signature


IDS = ('MSG-06-P', 'MSG-06-N01', 'MSG-06-N02', 'MSG-06-N03')
EFFECTS = {'protected_result_consumptions': 0, 'authorized_retries': 0,
           'downgrades': 0}
PEER = 'did:sage:web:agent.example:bob'


def check(root=ROOT):
    fixtures = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime',
                'MSG-06 fixture identity')
        fixtures[ident] = fixture

    control = fixtures['MSG-06-P']
    inp = control['input']['input']
    request = bytes.fromhex(inp['request_hex'])
    response = bytes.fromhex(inp['response_hex'])
    public = bytes.fromhex(inp['public_key_hex'])
    require(control['input']['operation'] == 'http.msg01.primitives' and
            set(inp) == {'request_hex', 'response_hex', 'public_key_hex',
                         'body_repeat'} and inp['body_repeat'] == 1,
            'MSG-06 signed primitive scope')
    source = load((root / 'vectors/0.10.0/http-boundaries.json').read_bytes())
    source_case = next(row for row in source['cases'] if
                       row['id'] == 'valid-signed-application-error')
    require(inp == {key: source_case['input'][key] for key in inp},
            'MSG-06 signed application failure source')
    request_base, request_sig, _ = base_and_signature(request)
    verify_signature(public, request_sig, request_base)
    base, _, request_body, headers, body = response_base(request, response)
    verify_signature(public, signature(headers), base)
    req_doc, resp_doc = json.loads(request_body), json.loads(body)
    require(resp_doc['success'] is False and
            resp_doc['error'] == 'operation_failed' and
            resp_doc['recipient'] == req_doc['did'] and
            resp_doc['did'] == PEER and
            resp_doc['request_hash'] == base64.urlsafe_b64encode(
                hashlib.sha256(json.dumps(req_doc, sort_keys=True,
                                          separators=(',', ':')).encode()).digest()
            ).decode().rstrip('=') and
            headers['content-digest'] == 'sha-256=:' +
            base64.b64encode(hashlib.sha256(body).digest()).decode() + ':' and
            control['expected'] == {'verdict': 'ACCEPT',
                                    'output': {'base_hex': base.hex(),
                                               'digest_valid': True},
                                    'effects': {}},
            'MSG-06 signed failure envelope and primitive expectation')

    generic = load((root / 'vectors/0.10.0/current-spec/MSG-06-generic-401.json')
                   .read_bytes())
    require(set(generic) == {'authentication', 'policy', 'replay'} and
            len(set(generic.values())) == 1, 'MSG-06 causes reveal response detail')
    common = bytes.fromhex(generic['authentication'])
    head, generic_body = common.split(b'\r\n\r\n', 1)
    require(head.startswith(b'HTTP/1.1 401 Unauthorized\r\n') and
            b'Content-Length: ' + str(len(generic_body)).encode() in head and
            json.loads(generic_body) == {'error': 'authentication_failed'} and
            b'Signature:' not in head and b'Signature-Input:' not in head,
            'MSG-06 generic unauthenticated 401 control')

    context = {'expected_response_did': PEER, 'trusted_now_unix': 1700000001,
               'transport_authenticated': True, 'consume_result': True}
    for ident in IDS[1:]:
        fixture = fixtures[ident]
        candidate = fixture['input']['input']
        require(fixture['input']['operation'] == 'sage.http.verify' and
                fixture['expected'] == {'verdict': 'REJECT', 'output': {},
                                        'effects': EFFECTS} and
                candidate['request_hex'] == inp['request_hex'] and
                candidate['public_key_hex'] == inp['public_key_hex'] and
                candidate['body_repeat'] == 1,
                'MSG-06 receiving boundary and no effects')
        expected_context = dict(context)
        if ident == 'MSG-06-N01':
            expected_context['failure_kind'] = 'authentication'
            detailed = bytes.fromhex(candidate['response_hex'])
            detail_head, detail_body = detailed.split(b'\r\n\r\n', 1)
            require(detail_head.startswith(b'HTTP/1.1 401 Unauthorized\r\n')
                    and b'Content-Length: ' + str(len(detail_body)).encode()
                    in detail_head and
                    json.loads(detail_body) == {'error': 'invalid_signature'} and
                    detailed != common,
                    'MSG-06 detailed authentication oracle')
        elif ident == 'MSG-06-N02':
            response_head, response_body = response.split(b'\r\n\r\n', 1)
            stripped = b'\r\n'.join(line for line in
                                    response_head.split(b'\r\n') if not
                                    line.startswith((b'Signature-Input: ',
                                                     b'Signature: ')))
            require(bytes.fromhex(candidate['response_hex']) ==
                    stripped + b'\r\n\r\n' + response_body,
                    'MSG-06 unsigned application failure')
        else:
            expected_context['transport_authenticated'] = False
            require(candidate['response_hex'] == inp['response_hex'],
                    'MSG-06 plaintext transport changes no signed bytes')
        require({key: value for key, value in candidate.items() if
                 key not in inp} == expected_context,
                'MSG-06 isolated receiving context: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print('Verified MSG-06 failure fixtures:', check())
