"""Check request-bound response, session mode, and terminal-state fixtures."""

import base64
import copy
import hashlib
import json

from current_spec_catalog import ROOT, load, require
from check_current_spec_card02_vectors import verified


IDS = ('TRANSPORT-03-P', 'TRANSPORT-03-N01', 'TRANSPORT-03-N02',
       'TRANSPORT-03-N03', 'TRANSPORT-03-N04', 'TRANSPORT-03-N05',
       'TRANSPORT-03-N06')
REQUEST_DOMAIN = b'sage-wire-request|0.10.0\n'
RESPONSE_DOMAIN = b'sage-wire-response|0.10.0\n'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def pair(fixture):
    fields = fixture['input']['input']
    request = load(bytes.fromhex(fields['stored_request_hex'])) \
        if fields['stored_request_hex'] else None
    response = load(bytes.fromhex(fields['response_hex']))
    return request, response


def source_envelope(row, kind):
    raw = bytes.fromhex(row['input'][kind + '_hex'])
    return load(raw.split(b'\r\n\r\n', 1)[1])


def signed(value, public, response):
    unsigned = copy.deepcopy(value)
    signature = base64.urlsafe_b64decode(unsigned.pop('signature') + '==')
    domain = RESPONSE_DOMAIN if response else REQUEST_DOMAIN
    return verified(public, signature, domain + canonical(unsigned))


def request_hash(value):
    return base64.urlsafe_b64encode(hashlib.sha256(canonical(value)).digest()
                                    ).decode().rstrip('=')


def check(root=ROOT):
    suite = load((root / 'vectors/0.10.0/http-boundaries.json').read_bytes())
    source = {row['id']: row for row in suite['cases']}
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    control_request = source_envelope(source['valid-response'], 'request')
    control_response = source_envelope(source['valid-response'], 'response')
    public = bytes.fromhex(source['valid-response']['input']['public_key_hex'])
    context = fixtures['TRANSPORT-03-P']['input']['input']
    require(context['trusted_keys'] == {
                control_request['kid']: public.hex(),
                control_response['kid']: public.hex()} and
            context['now'] == 1700000001 and context['clock_trusted'] is True,
            'TRANSPORT-03 pinned verifier context')
    for ident in IDS:
        fixture = fixtures[ident]
        fields = fixture['input']['input']
        req, res = pair(fixture)
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] == 'sage.transport.response.verify'
                and set(fields) == set(context) and
                all(fields[key] == context[key]
                    for key in ('now', 'clock_trusted', 'trusted_keys')) and
                fixture['expected'] == {
                    'verdict': 'ACCEPT' if ident == 'TRANSPORT-03-P' else 'REJECT',
                    'output': {'valid': True} if ident == 'TRANSPORT-03-P' else {},
                    'effects': {}},
                'TRANSPORT-03 fixture contract: ' + ident)
        require(signed(res, public, True) and
                (req is None or signed(req, public, False)),
                'TRANSPORT-03 independent inner signatures: ' + ident)
    positive_request, positive_response = pair(fixtures['TRANSPORT-03-P'])
    require(positive_request == control_request and
            positive_response == control_response and
            positive_response['message_id'] == positive_request['id'] and
            positive_response['request_hash'] == request_hash(positive_request),
            'TRANSPORT-03 complete signed-request hash control')
    wrong_request, wrong_response = pair(fixtures['TRANSPORT-03-N01'])
    require(wrong_request == control_request and
            wrong_response == source_envelope(source['wrong-request-hash'],
                                              'response') and
            wrong_response['request_hash'] != request_hash(wrong_request),
            'TRANSPORT-03 independently signed wrong request hash')
    session_request, plain_response = pair(fixtures['TRANSPORT-03-N02'])
    role_request, role_response = pair(fixtures['TRANSPORT-03-N03'])
    require(session_request == role_request and
            session_request['encoding'] == 'session' and
            session_request['role'] == 'initiator' and
            plain_response['encoding'] == 'plain' and
            'session_id' not in plain_response and
            plain_response['request_hash'] == request_hash(session_request) and
            plain_response['context_id'] == session_request['context_id'] and
            role_response['encoding'] == 'session' and
            role_response['session_id'] == session_request['session_id'] and
            role_response['context_id'] == session_request['context_id'] and
            role_response['request_hash'] == request_hash(session_request) and
            role_response['role'] == session_request['role'],
            'TRANSPORT-03 isolated session downgrade and wrong role')
    repeated_request, repeated_response = pair(fixtures['TRANSPORT-03-N04'])
    require(repeated_request == control_request and
            repeated_response == control_response and
            fixtures['TRANSPORT-03-N04']['input']['input']['already_accepted']
            is True and not context['already_accepted'],
            'TRANSPORT-03 second terminal acceptance state')
    error_request, error_response = pair(fixtures['TRANSPORT-03-N05'])
    require(error_request == control_request and
            error_response['success'] is False and
            'error' not in error_response and
            {key: value for key, value in error_response.items()
             if key not in ('success', 'signature')} ==
            {key: value for key, value in control_response.items()
             if key not in ('success', 'signature')},
            'TRANSPORT-03 missing error on false')
    absent_request, unsolicited = pair(fixtures['TRANSPORT-03-N06'])
    require(absent_request is None and unsolicited == control_response and
            fixtures['TRANSPORT-03-N06']['input']['input']
            ['stored_request_hex'] == '',
            'TRANSPORT-03 unsolicited response without retained request')
    spec = (root / 'verification/0.10.0/snapshot/spec/08-transport.md').read_text()
    require('JCS(complete signed request envelope)' in spec and
            'second acceptance' in spec and
            'response to a session-encoded request MUST use session encoding'
            in spec, 'pinned TRANSPORT-03 response binding rules')
    return len(IDS)


if __name__ == '__main__':
    print('Verified TRANSPORT-03 response fixtures:', check())
