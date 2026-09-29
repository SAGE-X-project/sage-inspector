"""Generate fixed PoP, KEM endorsement, and controller-boundary cases."""

import copy
import hashlib
import json
from pathlib import Path

from generate_registry_vectors import DID, NOW, entry, jcs


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'vectors/0.10.0/registry-records.json'
OUTPUT = ROOT / 'vectors/0.10.0/reg04-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('REG-04-P', 'REG-04-N01', 'REG-04-N02', 'REG-04-N03',
       'REG-04-N04')


def main():
    raw = SOURCE.read_bytes()
    source = {row['id']: row for row in json.loads(raw)['cases']}
    positive = copy.deepcopy(source['record-historical-False']['input'])
    pop = copy.deepcopy(source['pop-current']['input'])
    wrong_registry = {**pop, 'registry_id': 'web:other.example'}
    base = copy.deepcopy(source['authenticate-valid']['input']['record'])
    changed = copy.deepcopy(base)
    changed['controller'] = 'other-controller'
    changed['version'] = '2'
    controller = {'previous_record': base, 'candidate_record': changed,
                  'actor': base['controller'], 'expected_version': '1',
                  'operation': 'change-controller'}
    kem_signer = copy.deepcopy(base)
    kem_signer['keys'][0]['proof']['signer'] = DID + '#kem-1'
    invalid_key = copy.deepcopy(base)
    short_key = hashlib.sha256(b'public REG-04 short KEM').digest()[:31]
    invalid_key['keys'][0] = entry('kem-1', 'x25519', short_key, 'signing-1')
    record_base = {k: v for k, v in source['record-valid']['input'].items()
                   if k != 'record_hex'}
    cases = [
        ('REG-04-P', 'sage.registry.record.verify', positive, 'ACCEPT',
         {'valid': True},
         'historical signer verifies retained KEM endorsement on read'),
        ('REG-04-N01', 'sage.registry.pop.domain.verify', wrong_registry, 'REJECT', {},
         'same PoP cannot move to a different registry identifier'),
        ('REG-04-N02', 'sage.registry.lifecycle.apply', controller, 'REJECT', {},
         'valid PoP cannot transfer the record controller'),
        ('REG-04-N03', 'sage.registry.record.verify',
         {**record_base, 'record_hex': jcs(kem_signer).hex()}, 'REJECT', {},
         'X25519 KEM cannot claim to sign its own proof'),
        ('REG-04-N04', 'sage.registry.record.verify',
         {**record_base, 'record_hex': jcs(invalid_key).hex()}, 'REJECT', {},
         '31-byte X25519 public key rejected despite valid endorsement'),
    ]
    supplemental = [
        ('historical-message', source['authenticate-historical-False']['input'],
         'REJECT', 'revoked historical signer cannot authenticate new messages'),
        ('historical-new-endorsement',
         source['record-new-endorsement-False']['input'], 'REJECT',
         'revoked signer cannot endorse newly added KEM'),
        ('valid-pop', source['signing-1-signature-valid']['input'], 'ACCEPT',
         'unchanged domain challenge signature'),
        ('wrong-registry-signature',
         source['signing-1-signature-registry']['input'], 'REJECT',
         'same signature over changed registry challenge'),
    ]
    suite = {
        'schema_version': 1, 'spec_revision': SPEC,
        'source_sha256': hashlib.sha256(raw).hexdigest(),
        'scope': 'public fixed records and proofs; no mutation, registry write, or network access',
        'cases': [{'id': ident, 'operation': operation, 'input': inp,
                   'expected': {'verdict': verdict, 'output': output,
                                'effects': {}}, 'purpose': purpose}
                  for ident, operation, inp, verdict, output, purpose in cases],
        'supplemental': [{'name': name, 'input': inp, 'expected': verdict,
                          'purpose': purpose}
                         for name, inp, verdict, purpose in supplemental],
    }
    OUTPUT.write_text(json.dumps(suite, indent=2) + '\n')
    for case in suite['cases']:
        ident = case['id']
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime',
                   'input': {'operation': case['operation'],
                             'input': case['input']},
                   'expected': case['expected']}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    for ident in IDS:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')
    print('Generated', len(cases), 'REG-04 cases and', len(supplemental), 'controls')


if __name__ == '__main__':
    main()
