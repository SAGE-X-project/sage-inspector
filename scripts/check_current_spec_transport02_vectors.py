"""Check whole-request signature coverage and signer ownership fixtures."""

import base64
import copy
import json

from current_spec_catalog import ROOT, load, require
from check_current_spec_card02_vectors import verified


IDS = ('TRANSPORT-02-P', 'TRANSPORT-02-N01', 'TRANSPORT-02-N02',
       'TRANSPORT-02-N03', 'TRANSPORT-02-N04')
DOMAIN = b'sage-wire-request|0.10.0\n'


def request(fixture):
    return load(bytes.fromhex(fixture['input']['input']['request_hex']))


def unsigned(value):
    result = copy.deepcopy(value)
    result.pop('signature')
    return result


def primitive(value, public):
    message = DOMAIN + json.dumps(unsigned(value), sort_keys=True,
                                  separators=(',', ':'), ensure_ascii=False,
                                  allow_nan=False).encode()
    signature = base64.urlsafe_b64decode(value['signature'] + '==')
    return verified(public, signature, message)


def check(root=ROOT):
    source = load((root / 'vectors/0.10.0/http-boundaries.json').read_bytes())
    control_case = next(row for row in source['cases']
                        if row['id'] == 'valid-request')
    control = load(bytes.fromhex(control_case['input']['request_hex'])
                   .split(b'\r\n\r\n', 1)[1])
    public = bytes.fromhex(control_case['input']['public_key_hex'])
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    positive = request(fixtures['TRANSPORT-02-P'])
    require(unsigned(positive) == dict(unsigned(control),
                                       metadata={'purpose': 'read'}) and
            primitive(positive, public),
            'TRANSPORT-02 independently signed metadata control')
    baseline = unsigned(positive)
    context = fixtures['TRANSPORT-02-P']['input']['input']
    wrong_kid = 'did:sage:web:agent.example:bob#signing-1'
    require(context['trusted_keys'] == {
                positive['kid']: public.hex(), wrong_kid: public.hex()} and
            context['expected_recipient'] == positive['recipient'] and
            context['now'] == 1700000001 and context['clock_trusted'] is True,
            'TRANSPORT-02 pinned verifier context')
    for ident in IDS:
        fixture = fixtures[ident]
        fields = fixture['input']['input']
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] == 'sage.transport.request.verify'
                and set(fields) == set(context) and
                all(fields[key] == context[key]
                    for key in context if key != 'request_hex') and
                fixture['expected'] == {
                    'verdict': 'ACCEPT' if ident == 'TRANSPORT-02-P' else 'REJECT',
                    'output': {'valid': True} if ident == 'TRANSPORT-02-P' else {},
                    'effects': {}},
                'TRANSPORT-02 fixture contract: ' + ident)
    recipient = unsigned(request(fixtures['TRANSPORT-02-N01']))
    payload = unsigned(request(fixtures['TRANSPORT-02-N02']))
    stripped = unsigned(request(fixtures['TRANSPORT-02-N03']))
    signer = unsigned(request(fixtures['TRANSPORT-02-N04']))
    require(recipient.pop('recipient') ==
            'did:sage:web:agent.example:charlie' and
            recipient == {key: item for key, item in baseline.items()
                          if key != 'recipient'},
            'TRANSPORT-02 recipient change isolation')
    require(base64.urlsafe_b64decode(payload.pop('payload') + '==') ==
            b'{"tool":"list"}' and
            payload == {key: item for key, item in baseline.items()
                        if key != 'payload'},
            'TRANSPORT-02 payload change isolation')
    require(stripped == {key: item for key, item in baseline.items()
                        if key != 'metadata'},
            'TRANSPORT-02 metadata removal isolation')
    require(signer.pop('kid') == wrong_kid and
            signer == {key: item for key, item in baseline.items()
                       if key != 'kid'} and
            wrong_kid.split('#')[0] != positive['did'],
            'TRANSPORT-02 signer ownership isolation')
    require(all(request(fixtures[ident])['signature'] == positive['signature']
                and not primitive(request(fixtures[ident]), public)
                for ident in IDS[1:4]) and
            primitive(request(fixtures['TRANSPORT-02-N04']), public),
            'TRANSPORT-02 cryptographic coverage and wrong-kid distinction')
    spec = (root / 'verification/0.10.0/snapshot/spec/08-transport.md').read_text()
    require('JCS(request without signature)' in spec and
            'Every member, including sender, recipient, key reference' in spec
            and 'The signature algorithm comes from the' in spec,
            'pinned TRANSPORT-02 signed-request rule')
    return len(IDS)


if __name__ == '__main__':
    print('Verified TRANSPORT-02 signed-request fixtures:', check())
