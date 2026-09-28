"""Audit fixed HTTP outer/inner bindings without network or core assumptions."""

import base64
import copy
import hashlib
import json

from current_spec_catalog import ROOT, load, require, sha
from check_current_spec_card02_vectors import verified


IDS = ('TRANSPORT-05-P', 'TRANSPORT-05-N01', 'TRANSPORT-05-N02',
       'TRANSPORT-05-N03')
VARIANTS = ('control', 'matching-optional-id', 'nonce-mismatch',
            'created-mismatch', 'expires-mismatch', 'keyid-mismatch',
            'missing-outer', 'missing-inner', 'unsigned-id-projection')
PRIMARY = dict(zip(IDS, ('control', 'nonce-mismatch', 'missing-outer',
                         'unsigned-id-projection')))
GROUPS = {'control': IDS[0], 'matching-optional-id': IDS[0],
          'nonce-mismatch': IDS[1], 'created-mismatch': IDS[1],
          'expires-mismatch': IDS[1], 'keyid-mismatch': IDS[1],
          'missing-outer': IDS[2], 'missing-inner': IDS[2],
          'unsigned-id-projection': IDS[3]}
SOURCE = 'vectors/0.10.0/transport05-scenarios.json'
COMPONENTS = ('@method', '@target-uri', '@authority', 'content-type',
              'content-digest', 'x-sage-did', 'x-sage-version')


def parse(raw):
    head, body = raw.split(b'\r\n\r\n', 1)
    lines = head.decode('ascii').split('\r\n')
    headers = {}
    for line in lines[1:]:
        name, value = line.split(': ', 1)
        require(name.lower() not in headers, 'unique fixed HTTP headers')
        headers[name.lower()] = value
    require(lines[0] == 'POST https://agent.example/call?x=1 HTTP/1.1'
            and int(headers['content-length']) == len(body) and
            headers['content-digest'] == 'sha-256=:' + base64.b64encode(
                hashlib.sha256(body).digest()).decode() + ':',
            'fixed HTTP framing and exact body digest')
    return headers, load(body)


def signatures(raw, public):
    headers, body = parse(raw)
    outer = False
    params = {}
    signature_input = headers['signature-input']
    require(signature_input.startswith('sig1=(' + ' '.join(
        '"' + name + '"' for name in COMPONENTS) + ');'),
        'required outer component order')
    for part in signature_input.split(');', 1)[1].split(';'):
        key, value = part.split('=', 1)
        require(key not in params, 'unique signature parameters')
        params[key] = json.loads(value)
    require(set(params) == {'keyid', 'alg', 'created', 'expires',
                           'nonce', 'tag'} and
            params['alg'] == 'ed25519' and params['tag'] == 'sage-0.10.0',
            'signature parameter profile')
    if 'signature' in headers:
        values = {'@method': 'POST',
                  '@target-uri': 'https://agent.example/call?x=1',
                  '@authority': headers['host']}
        values.update(headers)
        base = ('\n'.join('"' + name + '": ' + values[name]
                          for name in COMPONENTS) +
                '\n"@signature-params": ' +
                signature_input.removeprefix('sig1=')).encode()
        signature = headers['signature'].removeprefix('sig1=:').removesuffix(':')
        outer = verified(public, base64.b64decode(signature, validate=True), base)
    inner = False
    if 'signature' in body:
        unsigned = copy.deepcopy(body)
        signature = base64.urlsafe_b64decode(unsigned.pop('signature') + '==')
        message = b'sage-wire-request|0.10.0\n' + json.dumps(
            unsigned, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False).encode()
        inner = verified(public, signature, message)
    return headers, body, params, outer, inner


def check(root=ROOT):
    source_raw = (root / 'vectors/0.10.0/http-boundaries.json').read_bytes()
    source = {row['id']: row for row in load(source_raw)['cases']}
    raw = (root / SOURCE).read_bytes()
    suite = load(raw)
    require(suite['schema_version'] == 1 and
            suite['spec_revision'] ==
            '5bcf511e604579afa63f434013447f44b6858828' and
            suite['source_sha256'] == sha(source_raw) and
            tuple(row['name'] for row in suite['variants']) == VARIANTS,
            'TRANSPORT-05 source and variant identity')
    variants = {row['name']: row for row in suite['variants']}
    public = bytes.fromhex(source['valid-request']['input']['public_key_hex'])
    control = bytes.fromhex(source['valid-request']['input']['request_hex'])
    require(bytes.fromhex(variants['control']['request_hex']) == control and
            bytes.fromhex(variants['nonce-mismatch']['request_hex']) ==
            bytes.fromhex(source['nonce-body-mismatch']['input']['request_hex']) and
            bytes.fromhex(variants['unsigned-id-projection']['request_hex']) ==
            bytes.fromhex(source['header-x-sage-message-id']['input']['request_hex']),
            'three independently audited source wires')
    control_headers, control_body, control_params, _, _ = signatures(control, public)
    for name in VARIANTS:
        row = variants[name]
        headers, body, params, outer, inner = signatures(
            bytes.fromhex(row['request_hex']), public)
        require(row['case_id'] == GROUPS[name] and
                row['expected_verdict'] == ('ACCEPT' if name in
                    ('control', 'matching-optional-id') else 'REJECT') and
                body.get('recipient') == control_body['recipient'],
                'TRANSPORT-05 closed expected case: ' + name)
        if name == 'missing-outer':
            require(not outer and inner and 'signature' not in headers and
                    body == control_body, 'missing outer signature')
        elif name == 'missing-inner':
            require(outer and not inner and 'signature' not in body and
                    {k: v for k, v in body.items()} ==
                    {k: v for k, v in control_body.items() if k != 'signature'},
                    'missing inner signature with valid outer binding')
        else:
            require(outer and inner and body == control_body,
                    'independently valid dual signatures: ' + name)
        differences = tuple(key for key in ('nonce', 'created', 'expires', 'keyid')
                            if params[key] != body['kid' if key == 'keyid' else key])
        expected = {'nonce-mismatch': ('nonce',),
                    'created-mismatch': ('created',),
                    'expires-mismatch': ('expires',),
                    'keyid-mismatch': ('keyid',)}.get(name, ())
        require(differences == expected and
                (name not in ('created-mismatch', 'expires-mismatch',
                              'keyid-mismatch') or
                 all(params[key] == control_params[key]
                     for key in ('nonce', 'created', 'expires', 'keyid')
                     if key not in expected)),
                'exact signed parameter/body mismatch: ' + name)
        projected = headers.get('x-sage-message-id')
        require((projected is None and name not in
                 ('matching-optional-id', 'unsigned-id-projection')) or
                (projected is not None and
                 (projected == body['id']) == (name == 'matching-optional-id')),
                'optional projection equality: ' + name)
        accepted = outer and inner and not differences and (
            projected is None or projected == body['id'])
        require((accepted and 'ACCEPT' or 'REJECT') == row['expected_verdict']
                and row['mismatch'] == {
                    'nonce-mismatch': 'nonce', 'created-mismatch': 'created',
                    'expires-mismatch': 'expires', 'keyid-mismatch': 'keyid',
                    'missing-outer': 'outer-signature',
                    'missing-inner': 'inner-signature',
                    'unsigned-id-projection': 'header-id'}.get(name),
                'unit-only joint acceptance: ' + name)
        if name not in ('missing-inner', 'matching-optional-id'):
            require(body == control_body, 'unchanged signed body: ' + name)
        if name in ('created-mismatch', 'expires-mismatch', 'keyid-mismatch'):
            require(headers['signature'] != control_headers['signature'],
                    'fresh signed outer parameter: ' + name)
    for ident, name in PRIMARY.items():
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        fields = fixture['input']['input']
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] == 'sage.transport.http.receive'
                and fields['request_hex'] == variants[name]['request_hex'] and
                fields['response_hex'] == '' and
                fields['public_key_hex'] == public.hex() and
                fields['expected_recipient'] == control_body['recipient'] and
                fields['trusted_keys'] == source['valid-request']['input']['trusted_keys']
                and fields['now_unix'] == 1700000001 and
                fields['clock_trusted'] is True and
                fixture['expected'] == {
                    'verdict': 'ACCEPT' if ident == 'TRANSPORT-05-P' else 'REJECT',
                    'output': {'valid': True} if ident == 'TRANSPORT-05-P' else {},
                    'effects': {'replay_reservations':
                                1 if ident == 'TRANSPORT-05-P' else 0,
                                'application_dispatches':
                                1 if ident == 'TRANSPORT-05-P' else 0}},
                'TRANSPORT-05 runtime binding: ' + ident)
    spec = (root / 'verification/0.10.0/snapshot/spec/08-transport.md').read_text()
    require('HTTP signature keyid, times and nonce MUST equal the' in spec and
            'One acceptance transaction covers both' in spec and
            'Routing and authorization MUST use verified body fields' in spec,
            'pinned TRANSPORT-05 binding and authority rules')
    return len(VARIANTS)


if __name__ == '__main__':
    print('Verified TRANSPORT-05 static HTTP variants:', check())
