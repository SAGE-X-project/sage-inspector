"""Check isolated closed-envelope, UUID, base64url, and metadata fixtures."""

import base64
import copy
import json
import re

from current_spec_catalog import ROOT, load, require
from check_current_spec_card02_vectors import verified


IDS = ('TRANSPORT-01-P', 'TRANSPORT-01-N01', 'TRANSPORT-01-N02',
       'TRANSPORT-01-N03', 'TRANSPORT-01-N04')
SOURCE_IDS = {'TRANSPORT-01-P': 'valid-request',
              'TRANSPORT-01-N01': 'unknown-member',
              'TRANSPORT-01-N03': 'padded-payload'}
DOMAIN = b'sage-wire-request|0.10.0\n'


def envelope(case):
    return load(bytes.fromhex(case['input']['input']['envelope_hex']))


def source_envelope(row):
    raw = bytes.fromhex(row['input']['request_hex'])
    return load(raw.split(b'\r\n\r\n', 1)[1])


def unsigned(value):
    result = copy.deepcopy(value)
    result.pop('signature')
    return result


def check(root=ROOT):
    suite = load((root / 'vectors/0.10.0/http-boundaries.json').read_bytes())
    source = {row['id']: row for row in suite['cases']}
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    control = source_envelope(source['valid-request'])
    context = fixtures['TRANSPORT-01-P']['input']['input']
    public = bytes.fromhex(source['valid-request']['input']['public_key_hex'])
    require(context['trusted_keys'] == {control['kid']: public.hex()} and
            context['expected_recipient'] == control['recipient'] and
            context['now'] == 1700000001 and context['clock_trusted'] is True,
            'TRANSPORT-01 pinned verifier context')
    for ident, source_id in SOURCE_IDS.items():
        require(envelope(fixtures[ident]) == source_envelope(source[source_id]),
                'TRANSPORT-01 independently signed HTTP source: ' + ident)
    for ident in IDS:
        fixture = fixtures[ident]
        candidate = envelope(fixture)
        candidate_context = fixture['input']['input']
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] == 'sage.transport.envelope.verify'
                and set(candidate_context) == set(context) and
                all(candidate_context[key] == context[key]
                    for key in context if key != 'envelope_hex') and
                fixture['expected'] == {
                    'verdict': 'ACCEPT' if ident == 'TRANSPORT-01-P' else 'REJECT',
                    'output': {'valid': True} if ident == 'TRANSPORT-01-P' else {},
                    'effects': {}},
                'TRANSPORT-01 fixture contract: ' + ident)
        signature = candidate['signature']
        require(type(signature) is str and
                re.fullmatch('[A-Za-z0-9_-]{86}', signature) is not None,
                'TRANSPORT-01 canonical signature encoding: ' + ident)
        raw_signature = base64.urlsafe_b64decode(signature + '==')
        canonical = json.dumps(unsigned(candidate), sort_keys=True,
                               separators=(',', ':'), ensure_ascii=False,
                               allow_nan=False).encode()
        require(len(raw_signature) == 64 and
                verified(public, raw_signature, DOMAIN + canonical),
                'TRANSPORT-01 independently verified signature: ' + ident)
    unknown = unsigned(envelope(fixtures['TRANSPORT-01-N01']))
    invalid_uuid = unsigned(envelope(fixtures['TRANSPORT-01-N02']))
    padded = unsigned(envelope(fixtures['TRANSPORT-01-N03']))
    metadata = unsigned(envelope(fixtures['TRANSPORT-01-N04']))
    baseline = unsigned(control)
    require(unknown.pop('unknown') is True and unknown == baseline,
            'TRANSPORT-01 isolated unknown field')
    require(invalid_uuid.pop('id') ==
            '11111111-1111-4111-7111-111111111111' and
            invalid_uuid == {key: value for key, value in baseline.items()
                             if key != 'id'},
            'TRANSPORT-01 invalid UUID variant')
    require(padded.pop('payload') == baseline['payload'] + '=' and
            padded == {key: value for key, value in baseline.items()
                       if key != 'payload'},
            'TRANSPORT-01 isolated base64url padding')
    require(metadata.pop('metadata') == {'note': 'a' * 1025} and
            metadata == baseline,
            'TRANSPORT-01 metadata value exceeds 1024 UTF-8 bytes')
    spec = (root / 'verification/0.10.0/snapshot/spec/08-transport.md').read_text()
    require('unknown top-level members MUST be rejected' in spec and
            'Canonical UUIDv4' in spec and
            'unpadded base64url' in spec and
            'string values at most 1024 bytes each' in spec,
            'pinned TRANSPORT-01 schema limits')
    return len(IDS)


if __name__ == '__main__':
    print('Verified TRANSPORT-01 envelope fixtures:', check())
