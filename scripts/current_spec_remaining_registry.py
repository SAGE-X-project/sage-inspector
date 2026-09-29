"""Bounded registry, DID projection and public problem-detail decisions."""

import base64
import binascii
import re


IDS = (
    'mrevision-did-consumer', 'mrevision-extra-jwk-authority',
    'mllm-kem-alg-valid', 'mllm-kem-alg-case', 'mllm-kem-selection',
    'mllm-pop-exact-bytes', 'mllm-pop-duplicate-field',
    'mllm-kem-signature-reject', 'mstand-problem-fields',
    'mstand-problem-type-publication',
)
PROBLEM_BASE = 'https://sage-x-project.github.io/sage-spec/errors/'
DID = 'did:sage:web:agents.example.com:alice'
PROBLEMS = {
    'id.malformed': ('Malformed identifier', 400),
    'id.unknown-kind': ('Unsupported registry kind', 400),
    'version.unsupported': ('Unsupported protocol version', 400),
    'record.not-found': ('Record not found', 404),
    'key.not-in-record': ('Key not found', 404),
    'record.unreachable': ('Registry unavailable', 502),
    'record.stale': ('Registry observation stale', 502),
    'record.invalid': ('Registry record invalid', 502),
    'size.exceeded': ('Input too large', 413),
}


def challenge(fields):
    result = b'sage-pop-0.10.0'
    for value in fields:
        result += len(value).to_bytes(2, 'big') + value
    return result


def pop_fields():
    return (b'sage-registry', b'agent-1', b'key-1',
            b'x25519', bytes(range(32)))


def sample(ident):
    if ident in ('mrevision-did-consumer',
                 'mrevision-extra-jwk-authority'):
        jwk = {'kty': 'OKP', 'crv': 'Ed25519',
               'x': base64.urlsafe_b64encode(bytes.fromhex(
                   'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325'
                   'af021a68f707511a')).rstrip(b'=').decode()}
        if ident == 'mrevision-extra-jwk-authority':
            jwk['d'] = 'private-field-must-be-rejected'
        return {'media_type': 'application/did+json',
                'document': {'id': DID,
                             'verificationMethod': [
                                 {'id': DID + '#key-1',
                                  'type': 'JsonWebKey2020',
                                  'controller': DID,
                                  'publicKeyJwk': jwk}],
                             'authentication': [DID + '#key-1'],
                             'assertionMethod': [DID + '#key-1'],
                             'keyAgreement': [], 'service': []},
                'consumer_accepted':
                ident == 'mrevision-did-consumer',
                'authoritative_projection_accepted':
                ident == 'mrevision-did-consumer'}
    if ident in ('mllm-kem-alg-valid', 'mllm-kem-alg-case'):
        return {'alg': 'x25519' if ident.endswith('-valid') else 'X25519',
                'public_key_bytes': 32, 'key_role': 'kem',
                'endorsed_by_active_signing_key': True,
                'accepted': ident.endswith('-valid')}
    if ident == 'mllm-kem-selection':
        return {'now': 100, 'keys': [
            {'name': 'a', 'alg': 'x25519', 'state': 'accepted', 'expires': 200},
            {'name': 'b', 'alg': 'x25519', 'state': 'accepted', 'expires': 200}],
            'selected_name': 'a'}
    if ident in ('mllm-pop-exact-bytes', 'mllm-pop-duplicate-field'):
        fields = pop_fields()
        encoded = challenge(fields)
        if ident == 'mllm-pop-duplicate-field':
            encoded += fields[-1]
        return {'fields_b64': [base64.b64encode(value).decode()
                               for value in fields],
                'challenge_hex': encoded.hex(),
                'accepted': ident == 'mllm-pop-exact-bytes'}
    if ident == 'mllm-kem-signature-reject':
        return {'algorithm': 'x25519', 'key_role': 'kem',
                'message_signature_accepted': False}
    if ident == 'mstand-problem-fields':
        return {'problems': [
            {'code': code, 'type': PROBLEM_BASE + code,
             'title': title, 'status': status,
             'http_status': status}
            for code, (title, status) in PROBLEMS.items()],
            'mismatched_status_accepted': False,
            'unknown_code_accepted': False}
    return {'published_types': [
        {'type': PROBLEM_BASE + code,
         'owner': 'SAGE-X-project/sage-spec',
         'human_readable': True, 'published_revision': 'pinned-deployment',
         'consumer': 'independent-rfc9457-reader',
         'consumer_accepted': True}
        for code in PROBLEMS]}


def check(ident, evidence):
    if ident not in IDS or type(evidence) is not dict or \
            set(evidence) != set(sample(ident)):
        return False
    if ident.startswith('mrevision-'):
        doc = evidence['document']
        if type(doc) is not dict or \
                set(doc) != {'id', 'verificationMethod', 'authentication',
                             'assertionMethod', 'keyAgreement', 'service'} or \
                evidence['media_type'] != 'application/did+json' or \
                type(doc['id']) is not str or \
                not re.fullmatch(r'did:sage:web:[a-z0-9.-]+:'
                                 r'[A-Za-z0-9._-]{1,64}', doc['id']) or \
                type(doc['verificationMethod']) is not list or \
                type(doc['authentication']) is not list or \
                type(doc['assertionMethod']) is not list or \
                type(doc['keyAgreement']) is not list or \
                type(doc['service']) is not list or \
                doc['keyAgreement'] or doc['service'] or \
                len(doc['verificationMethod']) != 1:
            return False
        method = doc['verificationMethod'][0]
        if type(method) is not dict or \
                set(method) != {'id', 'type', 'controller', 'publicKeyJwk'} or \
                type(method['id']) is not str or \
                method['id'] != doc['id'] + '#key-1' or \
                method['type'] != 'JsonWebKey2020' or \
                method['controller'] != doc['id'] or \
                doc['authentication'] != [method['id']] or \
                doc['assertionMethod'] != [method['id']]:
            return False
        jwk = method['publicKeyJwk']
        expected_members = ({'kty', 'crv', 'x'} if
                            ident == 'mrevision-did-consumer' else
                            {'kty', 'crv', 'x', 'd'})
        shape = (type(jwk) is dict and
                 set(jwk) == expected_members and
                 jwk['kty'] == 'OKP' and jwk['crv'] == 'Ed25519' and
                 type(jwk['x']) is str and len(jwk['x']) == 43)
        if shape:
            try:
                decoded = base64.b64decode(jwk['x'] + '=', altchars=b'-_',
                                           validate=True)
                shape = (len(decoded) == 32 and
                         base64.urlsafe_b64encode(decoded).rstrip(b'=').decode()
                         == jwk['x'])
            except (ValueError, binascii.Error):
                shape = False
        expected = ident == 'mrevision-did-consumer'
        return (shape and
                (expected or type(jwk['d']) is str) and
                evidence['consumer_accepted'] is expected and
                evidence['authoritative_projection_accepted'] is expected)
    if ident in ('mllm-kem-alg-valid', 'mllm-kem-alg-case'):
        valid = (evidence['alg'] == 'x25519' and
                 type(evidence['public_key_bytes']) is int and
                 evidence['public_key_bytes'] == 32 and
                 evidence['key_role'] == 'kem' and
                 evidence['endorsed_by_active_signing_key'] is True)
        return (evidence['accepted'] is valid and
                valid is ident.endswith('-valid'))
    if ident == 'mllm-kem-selection':
        keys = evidence['keys']
        if type(keys) is not list or len(keys) < 2 or len(keys) > 128 or \
                type(evidence['now']) is not int:
            return False
        try:
            if any(type(row) is not dict or
                   set(row) != {'name', 'alg', 'state', 'expires'} or
                   type(row['name']) is not str or not
                   re.fullmatch(r'[A-Za-z0-9_-]{1,32}', row['name'])
                   for row in keys):
                return False
            eligible = [row['name'] for row in keys
                        if row['alg'] == 'x25519' and
                        row['state'] == 'accepted' and
                        type(row['expires']) is int and
                        0 <= row['expires'] <= 9007199254740991 and
                        evidence['now'] < row['expires']]
            return (len(eligible) >= 2 and
                    len({row['name'] for row in keys}) == len(keys) and
                    evidence['selected_name'] == min(eligible))
        except (KeyError, TypeError):
            return False
    if ident in ('mllm-pop-exact-bytes', 'mllm-pop-duplicate-field'):
        try:
            if type(evidence['fields_b64']) is not list or \
                    len(evidence['fields_b64']) != 5 or \
                    any(type(value) is not str for value in evidence['fields_b64']):
                return False
            fields = tuple(base64.b64decode(value, validate=True)
                           for value in evidence['fields_b64'])
            if (any(len(value) > 65535 for value in fields) or
                    fields[0] != b'sage-registry' or
                    fields[3] != b'x25519' or len(fields[4]) != 32 or
                    any(not value or not value.isascii()
                        for value in fields[:4])):
                return False
            actual = bytes.fromhex(evidence['challenge_hex'])
        except (ValueError, TypeError, binascii.Error):
            return False
        expected = challenge(fields)
        valid = actual == expected
        if ident == 'mllm-pop-duplicate-field':
            return (actual == expected + fields[-1] and
                    evidence['accepted'] is False)
        return valid and evidence['accepted'] is True
    if ident == 'mllm-kem-signature-reject':
        return (evidence['algorithm'] == 'x25519' and
                evidence['key_role'] == 'kem' and
                evidence['message_signature_accepted'] is False)
    if ident == 'mstand-problem-fields':
        rows = evidence['problems']
        if type(rows) is not list or len(rows) != len(PROBLEMS) or \
                any(type(row) is not dict or
                    set(row) != {'code', 'type', 'title', 'status',
                                 'http_status'} or
                    type(row['code']) is not str or
                    row['code'] not in PROBLEMS for row in rows):
            return False
        return (set(row['code'] for row in rows) == set(PROBLEMS) and
                evidence['mismatched_status_accepted'] is False and
                evidence['unknown_code_accepted'] is False and
                all(type(row) is dict and
                    set(row) == {'code', 'type', 'title', 'status',
                                 'http_status'} and
                    row['type'] == PROBLEM_BASE + row['code'] and
                    (row['title'], row['status']) == PROBLEMS[row['code']] and
                    row['http_status'] == row['status']
                    for row in rows))
    rows = evidence['published_types']
    if type(rows) is not list or len(rows) != len(PROBLEMS) or \
            any(type(row) is not dict or
                set(row) != {'type', 'owner', 'human_readable',
                             'published_revision', 'consumer',
                             'consumer_accepted'} or
                type(row['type']) is not str for row in rows):
        return False
    return (set(row['type'] for row in rows) ==
            {PROBLEM_BASE + code for code in PROBLEMS} and
            all(type(row) is dict and
                row['owner'] == 'SAGE-X-project/sage-spec' and
                row['human_readable'] is True and
                type(row['published_revision']) is str and
                bool(row['published_revision']) and
                type(row['consumer']) is str and bool(row['consumer']) and
                row['consumer_accepted'] is True for row in rows))
