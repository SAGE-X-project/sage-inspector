"""Check exact HTTP boundary mutations without claiming receiving effects."""

import base64
import hashlib

from current_spec_catalog import ROOT, load, require
from check_current_spec_msg02_vectors import check as check_msg02


IDS = ('MSG-04-P', 'MSG-04-N01', 'MSG-04-N02', 'MSG-04-N03',
       'MSG-04-N04', 'MSG-04-N05')
BODY_LIMIT = 16 * 1024 * 1024
FIELD_LIMIT = 32 * 1024


def fields_size(request):
    head = request.split(b'\r\n\r\n', 1)[0]
    return sum(len(line) + 2 for line in head.split(b'\r\n')[1:])


def check(root=ROOT):
    require(check_msg02(root) == 6, 'MSG-04 control request signature')
    source = load((root / 'vectors/0.10.0/current-spec/MSG-02-P.json')
                  .read_bytes())
    fixtures = {}
    requests = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime',
                'MSG-04 fixture identity')
        inp = fixture['input']['input']
        require(inp['response_hex'] == '' and
                inp['public_key_hex'] == source['input']['input']['public_key_hex'],
                'MSG-04 key and request-only input')
        fixtures[ident] = fixture
        requests[ident] = bytes.fromhex(inp['request_hex'])

    control = requests['MSG-04-P']
    head, body = control.split(b'\r\n\r\n', 1)
    require(control == bytes.fromhex(source['input']['input']['request_hex']) and
            fixtures['MSG-04-P']['input']['operation'] ==
            'http.msg01.primitives' and
            fixtures['MSG-04-P']['expected'] == source['expected'] and
            len(body) <= BODY_LIMIT and fields_size(control) <= FIELD_LIMIT,
            'MSG-04 signed small control and primitive scope')

    for ident in IDS[1:]:
        fixture = fixtures[ident]
        inp = fixture['input']['input']
        require(fixture['input']['operation'] == 'sage.http.verify' and
                fixture['expected'] == {'verdict': 'REJECT', 'output': {},
                                        'effects': {'protected_dispatches': 0}} and
                inp['trusted_now_unix'] == 1700000010,
                'MSG-04 full receiving-boundary requirement')
        raw = requests[ident]
        if ident == 'MSG-04-N01':
            require(set(inp) == {'request_hex', 'response_hex',
                                 'public_key_hex', 'body_repeat',
                                 'trusted_now_unix'} and
                    inp['body_repeat'] == 1 and
                    raw == control.replace(b'Content-Type: application/json\r\n',
                        b'Content-Type: application/json\r\n'
                        b'Content-Type: application/json\r\n', 1),
                    'MSG-04 duplicate protected Content-Type')
        elif ident == 'MSG-04-N02':
            length = b'Content-Length: ' + str(len(body)).encode()
            encoded_body = (format(len(body), 'x').encode() + b'\r\n' + body +
                            b'\r\n0\r\n\r\n')
            require(inp['body_repeat'] == 1 and
                    raw == head.replace(length,
                        b'Transfer-Encoding: chunked\r\n' + length, 1) +
                        b'\r\n\r\n' + encoded_body and
                    b'Transfer-Encoding: chunked\r\n' in raw and
                    length in raw,
                    'MSG-04 contradictory transfer and content length')
        elif ident == 'MSG-04-N03':
            count = BODY_LIMIT + 1
            old_digest = next(line for line in head.split(b'\r\n')
                              if line.startswith(b'Content-Digest: '))
            new_digest = (b'Content-Digest: sha-256=:' +
                          base64.b64encode(hashlib.sha256(b'x' * count).digest())
                          + b':')
            expected = (head.replace(b'Content-Length: ' + str(len(body)).encode(),
                       b'Content-Length: ' + str(count).encode(), 1)
                       .replace(old_digest, new_digest, 1) + b'\r\n\r\nx')
            require(inp['body_repeat'] == count and raw == expected and
                    count > BODY_LIMIT and fields_size(raw) <= FIELD_LIMIT,
                    'MSG-04 compact one-byte oversize recipe')
        elif ident == 'MSG-04-N04':
            padding = FIELD_LIMIT + 1 - fields_size(control) - len(b'X-Padding: ') - 2
            require(inp['body_repeat'] == 1 and padding > 0 and
                    raw == control.replace(b'Host: agent.example\r\n',
                        b'X-Padding: ' + b'x' * padding +
                        b'\r\nHost: agent.example\r\n', 1) and
                    fields_size(raw) == FIELD_LIMIT + 1,
                    'MSG-04 exact HTTP field limit plus one')
        else:
            require(set(inp) == {'request_hex', 'response_hex',
                                 'public_key_hex', 'body_repeat',
                                 'trusted_now_unix', 'resolver_scenario'} and
                    inp['body_repeat'] == 1 and raw == control and
                    inp['resolver_scenario'] == 'timeout',
                    'MSG-04 injected resolver timeout without input mutation')
    return len(IDS)


if __name__ == '__main__':
    print('Verified MSG-04 boundary fixtures:', check())
