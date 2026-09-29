"""Translate fixed sage-spec wire/HTTP bytes into Inspector adapter cases."""

import base64
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'vectors/0.10.0/wire-http-binding-source.json'
OUTPUT = ROOT / 'vectors/0.10.0/wire-http-binding.json'
SOURCE_SHA256 = '17de2b6ca0eaf71cb7e1ad4c569b2a7b0e235f1ba9992c05fcacde86fbcf6a63'
SPEC_REVISION = '44df132fee5925182018ce089dc82435cb353f8a'
SPKI_ED25519 = bytes.fromhex('302a300506032b6570032100')


def require(condition, label):
    if not condition:
        raise ValueError(label)


def public_hex(row):
    der = base64.b64decode(row['public_spki_der_b64'], validate=True)
    require(der.startswith(SPKI_ED25519) and len(der) == len(SPKI_ED25519) + 32,
            'Ed25519 public key encoding')
    return der[len(SPKI_ED25519):].hex()


def raw_http(row, response=False):
    if response:
        start = 'HTTP/1.1 503 Service Unavailable'
        fields = [('Host', 'processor.example.com')]
    else:
        start = row['method'] + ' ' + row['target_uri'] + ' HTTP/1.1'
        fields = [('Host', row['authority'])]
    body = row['body_utf8'].encode('utf-8')
    fields.extend([
        ('Content-Type', row['content_type']),
        ('Content-Digest', row['content_digest']),
        ('X-SAGE-DID', row['x_sage_did']),
        ('X-SAGE-Version', row['x_sage_version']),
        ('Content-Length', str(len(body))),
        ('Signature-Input', row['signature_input']),
        ('Signature', row['signature_field']),
    ])
    head = start + '\r\n' + ''.join(name + ': ' + value + '\r\n'
                                   for name, value in fields) + '\r\n'
    return head.encode('ascii') + body


def build_suite(source):
    require(source['schema_version'] == 1 and
            source['kind'] == 'wire-http-binding-independent-fixture' and
            source['protocol_version'] == '0.10.0' and
            source['status'] == 'OFFLINE_REFERENCE_NOT_PROTOCOL_CONFORMANCE',
            'source identity or evidence status')
    req, res = source['http_request'], source['http_response']
    initiator = public_hex(source['public_keys']['initiator'])
    responder = public_hex(source['public_keys']['responder'])
    request = raw_http(req)
    response = raw_http(res, response=True)
    keys = {
        source['public_keys']['initiator']['kid']: initiator,
        source['public_keys']['responder']['kid']: responder,
    }
    common = {'request_hex': request.hex(), 'response_hex': '',
              'public_key_hex': initiator, 'body_repeat': 1}
    reply = {**common, 'response_hex': response.hex(),
             'public_key_hex': responder}
    boundary = {**common, 'now_unix': source['reference_now'],
                'clock_trusted': True, 'expected_target': req['target_uri'],
                'expected_recipient': source['public_keys']['responder']['did'],
                'trusted_keys': keys}
    boundary_reply = {**boundary, 'response_hex': response.hex(),
                      'public_key_hex': responder}

    def case(name, operation, rules, input_value, expected, explanation):
        return {'id': name, 'operation': operation, 'rule_ids': rules,
                'source_ids': ['sage-wire-http'], 'derivation': explanation,
                'input': input_value, 'expected': expected}

    accepted = lambda output: {'verdict': 'ACCEPT', 'output': output}
    source_note = ('Fixed sage-spec bytes and expectations at ' + SPEC_REVISION +
                   '; partial boundary evidence only.')
    return {
        'schema_version': 1, 'protocol_version': '0.10.0',
        'profile': 'primitive-foundation',
        'id': 'sage-wire-http-binding-0.10.0',
        'sources': [{'id': 'sage-wire-http', 'kind': 'spec-derived',
                     'uri': 'sage-spec/verification/vectors/wire-http-binding-0.10.0.json',
                     'reference': SPEC_REVISION + ' SHA-256 ' + SOURCE_SHA256 +
                                  '; offline reference, not core conformance.'}],
        'cases': [
            case('wire-http-request-base', 'rfc9421.base', ['MSG-02'],
                 common, accepted({'base_hex': req['signature_base_ascii'].encode('ascii').hex()}),
                 'Exact RFC 9421 request base. ' + source_note),
            case('wire-http-response-base', 'rfc9421.base', ['MSG-03'],
                 reply, accepted({'base_hex': res['signature_base_ascii'].encode('ascii').hex()}),
                 'Exact request-bound RFC 9421 response base. ' + source_note),
            case('wire-http-request-digest', 'sage.content-digest', ['MSG-01'],
                 common, accepted({'valid': True}),
                 'Digest of received request body bytes. ' + source_note),
            case('wire-http-response-digest', 'sage.content-digest', ['MSG-01'],
                 reply, accepted({'valid': True}),
                 'Digest of received response body bytes. ' + source_note),
            case('wire-http-request-boundary', 'sage.http.verify',
                 ['MSG-04', 'TRANSPORT-02', 'TRANSPORT-05'],
                 boundary, accepted({'valid': True}),
                 'Dual-signature request boundary; requires subject implementation. ' + source_note),
            case('wire-http-response-boundary', 'sage.http.verify',
                 ['MSG-04', 'TRANSPORT-03', 'TRANSPORT-05'],
                 boundary_reply, accepted({'valid': True}),
                 'Dual-signature signed-unavailable response boundary; requires subject implementation. ' + source_note),
        ],
    }


def check(root=ROOT, spec_root=None):
    raw = (root / SOURCE.relative_to(ROOT)).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'source fixture hash')
    if spec_root is not None:
        upstream = spec_root / 'verification/vectors/wire-http-binding-0.10.0.json'
        require(upstream.read_bytes() == raw, 'pinned sage-spec fixture differs')
    source = json.loads(raw)
    expected = (json.dumps(build_suite(source), indent=2) + '\n').encode()
    require((root / OUTPUT.relative_to(ROOT)).read_bytes() == expected,
            'derived suite bytes differ')
    return {'cases': 6, 'boundary_cases': 2,
            'source_sha256': SOURCE_SHA256,
            'implementation_conformance': 'NOT_ESTABLISHED'}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--spec-root', type=Path)
    args = parser.parse_args()
    if args.write:
        raw = SOURCE.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == SOURCE_SHA256,
                'source fixture hash')
        OUTPUT.write_text(json.dumps(build_suite(json.loads(raw)), indent=2) + '\n')
    print(json.dumps(check(spec_root=args.spec_root), sort_keys=True))
