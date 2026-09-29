"""Generate bounded signature-suite identifier and role-selection fixtures."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('TABLE-02-P', 'TABLE-02-N01', 'TABLE-02-N02')


def registered_suites():
    return [
        {'alg': 'ed25519', 'key_type': 'Ed25519', 'digest': 'none',
         'signature_bytes': 64, 'encoding': 'R-S', 'status': 'mandatory'},
        {'alg': 'sage-secp256k1-keccak256', 'key_type': 'secp256k1',
         'digest': 'Keccak-256', 'signature_bytes': 65,
         'encoding': 'r-s-v-low-s', 'status': 'optional'},
        {'alg': 'ecdsa-p256-sha256', 'key_type': 'P-256',
         'digest': 'SHA-256', 'signature_bytes': 64,
         'encoding': 'r-s-low-s', 'status': 'optional'},
    ]


def main():
    suites = registered_suites()
    positive = {
        'registered_suites': suites,
        'implementation_support': {
            'ed25519': True, 'sage-secp256k1-keccak256': True,
            'ecdsa-p256-sha256': False},
        'request': {
            'alg': 'sage-secp256k1-keccak256', 'key_type': 'secp256k1',
            'digest': 'Keccak-256', 'signature_bytes': 65,
            'encoding': 'r-s-v-low-s', 'jose_alias': None,
            'usage': 'message-signature', 'wire_scope': 'external'}}
    legacy = copy.deepcopy(positive)
    legacy['request']['alg'] = 'es256k'
    inferred_jose = copy.deepcopy(positive)
    inferred_jose['request']['jose_alias'] = 'ES256K'
    rows = [
        ('TABLE-02-P', positive, 'ACCEPT', 'exact SAGE secp256k1 suite mapping'),
        ('TABLE-02-N01', legacy, 'REJECT', 'obsolete es256k identifier'),
        ('TABLE-02-N02', inferred_jose, 'REJECT', 'private Keccak suite aliased to JOSE ES256K'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': {'selected_suite': suites[1]} if verdict == 'ACCEPT' else {},
                    'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'runtime',
                   'input': {'operation': 'sage.crypto.signature.suite.select',
                             'input': inp}, 'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'registries_sha256': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
             'crypto_sha256': 'fe9fd00066b259b99a63e5adab7db739757e3ad2597ccc71e2019fa34319faec',
             'scope': 'synthetic algorithm dispatch; no signature generation, verification, or deployed optional-suite claim',
             'cases': cases}
    (ROOT / 'vectors/0.10.0/table02-scenarios.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident in IDS:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
