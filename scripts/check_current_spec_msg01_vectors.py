"""Independently verify bounded HTTP signature fixtures and exact mutations."""

import base64
import hashlib
from pathlib import Path
import subprocess
import tempfile

from current_spec_catalog import ROOT, load, require


IDS = ('MSG-01-P', 'MSG-01-N01', 'MSG-01-N02', 'MSG-01-N03', 'MSG-01-N04')
SPKI_ED25519 = bytes.fromhex('302a300506032b6570032100')
COVERED = ('@method', '@target-uri', '@authority', 'content-type',
           'content-digest', 'x-sage-did', 'x-sage-version')


def verify_signature(public, signature, message):
    require(len(public) == 32 and len(signature) == 64, 'Ed25519 key or signature length')
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        (base / 'public.der').write_bytes(SPKI_ED25519 + public)
        (base / 'message').write_bytes(message)
        (base / 'signature').write_bytes(signature)
        result = subprocess.run(
            ['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey',
             str(base / 'public.der'), '-keyform', 'DER', '-rawin', '-in',
             str(base / 'message'), '-sigfile', str(base / 'signature')],
            capture_output=True, timeout=5, check=False)
    require(result.returncode == 0, 'invalid MSG-01 Ed25519 signature')


def check(root=ROOT):
    fixtures = {}
    requests = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime',
                'MSG-01 fixture identity')
        inp = fixture['input']['input']
        require(set(inp) == {'request_hex', 'response_hex', 'public_key_hex',
                             'body_repeat'} and inp['response_hex'] == '' and
                inp['body_repeat'] == 1, 'MSG-01 input envelope')
        fixtures[ident] = fixture
        requests[ident] = bytes.fromhex(inp['request_hex']).decode('ascii')

    positive = fixtures['MSG-01-P']
    require(positive['input']['operation'] == 'http.msg01.primitives' and
            positive['expected']['verdict'] == 'ACCEPT' and
            positive['expected']['output']['digest_valid'] is True,
            'MSG-01 positive primitive scope')
    control = requests['MSG-01-P']
    head, body = control.split('\r\n\r\n', 1)
    lines = head.split('\r\n')
    require(lines[0] == 'POST https://agent.example/call?x=1 HTTP/1.1' and
            body == '{}' and len(lines) == 9, 'MSG-01 control framing')
    headers = {}
    for line in lines[1:]:
        name, value = line.split(': ', 1)
        name = name.lower()
        require(name not in headers, 'duplicate MSG-01 control header')
        headers[name] = value
    digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
    require(headers['content-digest'] == 'sha-256=:' + digest + ':' and
            headers['content-length'] == str(len(body)) and
            headers['x-sage-version'] == '0.10.0', 'MSG-01 content binding')
    params = headers['signature-input']
    require(params.startswith('sig1=(' + ' '.join('"' + name + '"' for name in COVERED) + ')')
            and params.count(';keyid=') == params.count(';alg=') ==
            params.count(';created=') == params.count(';expires=') ==
            params.count(';nonce=') == params.count(';tag=') == 1 and
            ';alg="ed25519"' in params and params.endswith(';tag="sage-0.10.0"'),
            'MSG-01 signature parameters')
    values = {'@method': 'POST', '@target-uri': 'https://agent.example/call?x=1',
              '@authority': headers['host']}
    values.update(headers)
    base = ('\n'.join('"' + name + '": ' + values[name] for name in COVERED) +
            '\n"@signature-params": ' + params.removeprefix('sig1=')).encode()
    require(positive['expected']['output']['base_hex'] == base.hex(),
            'MSG-01 expected signature base')
    public = bytes.fromhex(positive['input']['input']['public_key_hex'])
    sig1 = headers['signature'].removeprefix('sig1=:').removesuffix(':')
    verify_signature(public, base64.b64decode(sig1, validate=True), base)

    for ident in IDS[1:]:
        fixture = fixtures[ident]
        inp = fixture['input']['input']
        require(inp['public_key_hex'] == positive['input']['input']['public_key_hex']
                and inp['response_hex'] == '' and inp['body_repeat'] == 1 and
                fixture['expected']['verdict'] == 'REJECT',
                'MSG-01 negative trusted context')
        candidate = requests[ident]
        if ident == 'MSG-01-N01':
            require(fixture['input']['operation'] == 'sage.http.verify' and
                    candidate.replace(', sig2=("@method");' + params.split(';', 1)[1], '')
                    .replace(', sig2=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:', '') == control,
                    'MSG-01 second signature mutation')
            verify_signature(public, base64.b64decode(sig1), base)
        elif ident == 'MSG-01-N02':
            require(fixture['input']['operation'] == 'sage.http.verify' and
                    candidate == control.replace(';tag="sage-0.10.0"\r\nSignature:',
                    ';tag="sage-0.10.0";created=1700000000\r\nSignature:'),
                    'MSG-01 duplicate SAGE parameter mutation')
        elif ident == 'MSG-01-N03':
            require(fixture['input']['operation'] == 'sage.http.verify',
                    'MSG-01 unknown parameter operation')
            extra_base = base + b';extra=1'
            extra_head = candidate.split('\r\n\r\n', 1)[0]
            extra_sig = next(line.removeprefix('Signature: sig1=:').removesuffix(':')
                             for line in extra_head.split('\r\n')
                             if line.startswith('Signature: '))
            require(candidate.replace(';extra=1\r\nSignature:', '\r\nSignature:')
                    .replace(extra_sig, sig1) == control,
                    'MSG-01 unknown parameter mutation')
            verify_signature(public, base64.b64decode(extra_sig, validate=True),
                             extra_base)
        else:
            require(fixture['input']['operation'] == 'sage.content-digest' and
                    candidate == control.replace(digest + ':', digest.rstrip('=') + ':'),
                    'MSG-01 digest encoding mutation')
    return len(IDS)


if __name__ == '__main__':
    print('Verified MSG-01 fixtures:', check())
