"""Verify independently signed Guard integer boundary fixtures."""

import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile

from current_spec_catalog import ROOT, load, require


IDS = ('JCS-02-P', 'JCS-02-N01', 'JCS-02-N02', 'JCS-02-N03', 'JCS-02-N04')
FIELDS = {'JCS-02-P': None, 'JCS-02-N01': 'created',
          'JCS-02-N02': 'created', 'JCS-02-N03': 'expires',
          'JCS-02-N04': 'created'}
MAX_SAFE = 9007199254740991
SPKI_ED25519 = bytes.fromhex('302a300506032b6570032100')


def verify_signature(inp, envelope):
    public = bytes.fromhex(inp['public_key_hex'])
    require(len(public) == 32, 'Ed25519 public key length')
    signature = base64.urlsafe_b64decode(envelope['proof'] + '==')
    require(len(signature) == 64, 'Ed25519 signature length')
    message = b'sage-execution-intent|0.10.0\0' + json.dumps(
        envelope['intent'], sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()
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
    require(result.returncode == 0, 'invalid signed Guard integer fixture')


def check(root=ROOT):
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] == 'guard.integer_pair',
                'JCS integer fixture identity')
        pair = fixture['input']['input']
        require(set(pair) == {'control', 'candidate'}, 'JCS integer pair')
        decoded = {}
        for role in ('control', 'candidate'):
            inp = pair[role]
            envelope = load(bytes.fromhex(inp['envelope_hex']))
            require(set(envelope) == {'intent', 'proof'} and
                    type(envelope['intent']) is dict,
                    'closed signed intent fixture')
            verify_signature(inp, envelope)
            decoded[role] = envelope['intent']
        control = decoded['control']
        candidate = decoded['candidate']
        normalized = copy.deepcopy(candidate)
        field = FIELDS[ident]
        if field is not None:
            normalized[field] = control[field]
        require(normalized == control, 'JCS integer candidate changed another intent field')
        for name in pair['control']:
            if name != 'envelope_hex':
                require(pair['control'][name] == pair['candidate'][name],
                        'JCS integer trusted input drift')
        require(type(control['created']) is int and type(control['expires']) is int and
                0 <= control['created'] < control['expires'] <= MAX_SAFE and
                control['expires'] - control['created'] <= 300,
                'invalid signed control interval')
        if ident == 'JCS-02-N01':
            require(type(candidate['created']) is float and
                    not candidate['created'].is_integer(), 'missing fractional mutation')
        elif ident == 'JCS-02-N02':
            require(type(candidate['created']) is int and
                    candidate['created'] < 0, 'missing negative mutation')
        elif ident == 'JCS-02-N03':
            require(type(candidate['expires']) is int and
                    candidate['expires'] == MAX_SAFE + 1,
                    'missing unsafe integer mutation')
        elif ident == 'JCS-02-N04':
            require(type(candidate['created']) is str,
                    'missing JSON type mutation')
        else:
            require(control == candidate and control['expires'] == MAX_SAFE,
                    'missing safe-range boundary control')
    return len(IDS)


if __name__ == '__main__':
    print('Verified signed Guard integer fixtures:', check())
