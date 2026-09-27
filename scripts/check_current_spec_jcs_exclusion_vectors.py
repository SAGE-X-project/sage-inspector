"""Check exact proof-member mutations against a valid signed Agent Card."""

import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile

from current_spec_catalog import ROOT, load, require


IDS = ('JCS-04-P', 'JCS-04-N01', 'JCS-04-N02', 'JCS-04-N03')
SPKI_ED25519 = bytes.fromhex('302a300506032b6570032100')


def verify_card(card, record):
    proof = card['proof']
    require(proof['alg'] == 'ed25519' and
            proof['type'] == 'SageAgentCardSignature0_10_0',
            'signed card proof profile')
    key = next((key for key in record['keys']
                if card['id'] + '#' + key['name'] == proof['verificationMethod']), None)
    require(key is not None and key['alg'] == 'ed25519' and
            key['state'] == 'accepted', 'signed card registry key')
    unsigned = copy.deepcopy(card)
    unsigned['proof'].pop('proofValue')
    message = b'sage-card-0.10.0\0' + json.dumps(
        unsigned, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()
    public = base64.urlsafe_b64decode(key['key'] + '==')
    signature = base64.urlsafe_b64decode(proof['proofValue'] + '==')
    require(len(public) == 32 and len(signature) == 64,
            'signed card Ed25519 lengths')
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
    require(result.returncode == 0, 'invalid signed Agent Card control')


def check(root=ROOT):
    fixtures = {}
    cards = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] == 'sage.card.verify',
                'JCS exclusion fixture identity')
        fixtures[ident] = fixture['input']['input']
        cards[ident] = load(bytes.fromhex(fixtures[ident]['card_hex']))
    control = cards['JCS-04-P']
    inp = fixtures['JCS-04-P']
    require(control['id'] == inp['expected_peer'] and
            control['recordVersion'] == inp['record']['version'] and
            control['services'] == inp['record']['services'] and
            inp['clock_trusted'] is True and
            control['issued'] <= inp['now'] < control['expires'],
            'Agent Card control binding')
    verify_card(control, inp['record'])
    for ident in IDS[1:]:
        require(all(fixtures[ident][key] == inp[key] for key in inp
                    if key != 'card_hex'), 'JCS exclusion trusted context drift')
        candidate = copy.deepcopy(cards[ident])
        if ident == 'JCS-04-N01':
            require('verificationMethod' not in candidate['proof'],
                    'missing proof metadata mutation')
            candidate['proof']['verificationMethod'] = control['proof']['verificationMethod']
        elif ident == 'JCS-04-N02':
            require('proof' not in candidate, 'missing proof object mutation')
            candidate['proof'] = control['proof']
        else:
            require(candidate['proof']['alg'] == 'ecdsa-p256-sha256',
                    'missing authenticated algorithm mutation')
            candidate['proof']['alg'] = control['proof']['alg']
        require(candidate == control, 'JCS exclusion changed another card field')
    return len(IDS)


if __name__ == '__main__':
    print('Verified exact Agent Card exclusion fixtures:', check())
