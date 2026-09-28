"""Check CARD-02 proof metadata, domain, and signature fixtures."""

import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile

from current_spec_catalog import ROOT, load, require
from check_current_spec_jcs_exclusion_vectors import SPKI_ED25519, verify_card


SOURCE_IDS = {
    'CARD-02-P': 'card-valid',
    'CARD-02-N01': 'card-legacy-proof',
    'CARD-02-N02': 'card-wrong-key',
}
IDS = ('CARD-02-P', 'CARD-02-N01', 'CARD-02-N02',
       'CARD-02-N03', 'CARD-02-N04')
CORRECT_DOMAIN = b'sage-card-0.10.0\0'
WRONG_DOMAIN = b'sage-card-0.9.0\0'


def verified(public, signature, message):
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        (base / 'public.der').write_bytes(SPKI_ED25519 + public)
        (base / 'signature').write_bytes(signature)
        (base / 'message').write_bytes(message)
        result = subprocess.run(
            ['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey',
             str(base / 'public.der'), '-keyform', 'DER', '-rawin', '-in',
             str(base / 'message'), '-sigfile', str(base / 'signature')],
            capture_output=True, timeout=5, check=False)
    return result.returncode == 0


def check(root=ROOT):
    source = load((root / 'vectors/0.10.0/registry-records.json').read_bytes())
    records = {row['id']: row for row in source['cases']}
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    for ident in IDS:
        require(fixtures[ident]['id'] == ident and
                fixtures[ident]['track'] == 'runtime' and
                fixtures[ident]['input']['operation'] == 'sage.card.verify',
                'CARD-02 fixture identity: ' + ident)
    for ident, source_id in SOURCE_IDS.items():
        record = records[source_id]
        require(fixtures[ident]['input']['input'] == record['input'] and
                fixtures[ident]['expected'] == dict(record['expected'], effects={}),
                'CARD-02 independent card source: ' + ident)
    control_input = records['card-valid']['input']
    control = load(bytes.fromhex(control_input['card_hex']))
    verify_card(control, control_input['record'])
    key = next(row for row in control_input['record']['keys']
               if row['name'] == 'signing-1')
    public = base64.urlsafe_b64decode(key['key'] + '==')
    unsigned = copy.deepcopy(control)
    signature = base64.urlsafe_b64decode(
        unsigned['proof'].pop('proofValue') + '==')
    canonical = json.dumps(unsigned, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False).encode()
    primitive = records['card-signature-primitive']['input']
    require(primitive['algorithm'] == 'ed25519' and
            primitive['public_key_hex'] == public.hex() and
            primitive['message_hex'] == (CORRECT_DOMAIN + canonical).hex() and
            primitive['signature_hex'] == signature.hex(),
            'CARD-02 independent signature primitive source')
    require(verified(public, signature, CORRECT_DOMAIN + canonical),
            'CARD-02 valid signature domain')
    legacy = load(bytes.fromhex(fixtures['CARD-02-N01']['input']['input']
                                ['card_hex']))
    wrong_key = load(bytes.fromhex(fixtures['CARD-02-N02']['input']['input']
                                   ['card_hex']))
    for ident in IDS[1:]:
        candidate_input = fixtures[ident]['input']['input']
        require(all(candidate_input[field] == control_input[field]
                    for field in control_input if field != 'card_hex') and
                fixtures[ident]['expected'] == {
                    'verdict': 'REJECT', 'output': {}, 'effects': {}},
                'CARD-02 trusted context and verdict: ' + ident)
    require(legacy['proof']['type'] == 'Ed25519Signature2020' and
            wrong_key['proof']['verificationMethod'] ==
                control['id'] + '#missing' and
            legacy['proof']['alg'] == wrong_key['proof']['alg'] == 'ed25519',
            'CARD-02 forbidden suite and absent selected key')
    domain = load(bytes.fromhex(fixtures['CARD-02-N03']['input']['input']
                                 ['card_hex']))
    domain_signature = base64.urlsafe_b64decode(
        domain['proof'].pop('proofValue') + '==')
    require(domain == unsigned and len(domain_signature) == 64 and
            verified(public, domain_signature, WRONG_DOMAIN + canonical) and
            not verified(public, domain_signature, CORRECT_DOMAIN + canonical),
            'CARD-02 wrong-domain signature isolation')
    malformed = load(bytes.fromhex(fixtures['CARD-02-N04']['input']['input']
                                    ['card_hex']))
    require(malformed['proof'].pop('proofValue') == '*' and
            malformed == unsigned,
            'CARD-02 malformed base64url signature isolation')
    spec = (root / 'verification/0.10.0/snapshot/spec/07-a2a.md').read_text()
    require('`SageAgentCardSignature0_10_0`' in spec and
            'only `proof.proofValue` removed' in spec and
            'sage-card-0.10.0' in spec and
            'canonical unpadded base64url' in spec,
            'pinned CARD-02 proof and domain rules')
    return len(IDS)


if __name__ == '__main__':
    print('Verified CARD-02 proof fixtures:', check())
