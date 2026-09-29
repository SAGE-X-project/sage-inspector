"""Generate public Registry key-selection and identity-transition fixtures."""

import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

from generate_registry_vectors import DID, NOW, entry, jcs, public


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'vectors/0.10.0/registry-records.json'
OUTPUT = ROOT / 'vectors/0.10.0/reg02-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('REG-02-P', 'REG-02-N01', 'REG-02-N02', 'REG-02-N03')


def main():
    source = SOURCE.read_bytes()
    rows = {row['id']: row for row in json.loads(source)['cases']}
    first = copy.deepcopy(rows['kem-select-first-ascii']['input'])
    unproven = copy.deepcopy(first)
    unproven['record']['keys'][0]['proof']['value'] = (
        'A' + unproven['record']['keys'][0]['proof']['value'][1:])
    revoked = copy.deepcopy(rows['authenticate-historical-False']['input'])
    previous = copy.deepcopy(first['record'])
    candidate = copy.deepcopy(previous)
    candidate['version'] = '2'
    replacement = public(x25519.X25519PrivateKey.from_private_bytes(
        hashlib.sha256(b'public REG-02 replacement KEM').digest()))
    candidate['keys'][0] = entry('kem-0', 'x25519', replacement, 'signing-1')
    cases = [
        ('REG-02-P', 'sage.registry.kem.select', first,
         'ACCEPT', {'keyid': DID + '#kem-0'},
         'first accepted and unexpired X25519 key in ASCII name order'),
        ('REG-02-N01', 'sage.registry.kem.select', unproven,
         'REJECT', {}, 'selected key has invalid proof despite valid later KEM'),
        ('REG-02-N02', 'sage.registry.authenticate', revoked,
         'REJECT', {}, 'revoked named Ed25519 key cannot authenticate'),
        ('REG-02-N03', 'sage.registry.key.transition.verify',
         {'previous_record': previous, 'candidate_record': candidate,
          'keyid': DID + '#kem-0', 'now': NOW},
         'REJECT', {}, 'new valid proof cannot replace existing named key material'),
    ]
    controls = [
        ('no-kem', rows['kem-select-no-kem']['input'], 'REJECT',
         'signing key is never selected as KEM'),
        ('revoked-first', rows['kem-select-first-revoked']['input'],
         'ACCEPT', 'later accepted KEM is eligible'),
        ('expired-first', rows['kem-select-first-expired']['input'],
         'ACCEPT', 'later unexpired KEM is eligible'),
    ]
    suite = {
        'schema_version': 1, 'spec_revision': SPEC,
        'source_sha256': hashlib.sha256(source).hexdigest(),
        'scope': 'public fixed records and local comparisons; no registry mutation or network access',
        'cases': [{'id': ident, 'operation': operation, 'input': inp,
                   'expected': {'verdict': verdict, 'output': output, 'effects': {}},
                   'purpose': purpose}
                  for ident, operation, inp, verdict, output, purpose in cases],
        'supplemental': [{'name': name, 'input': inp, 'expected': verdict,
                          'purpose': purpose}
                         for name, inp, verdict, purpose in controls],
    }
    OUTPUT.write_text(json.dumps(suite, indent=2) + '\n')
    for case in suite['cases']:
        ident = case['id']
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime', 'input': {'operation': case['operation'],
                                                'input': case['input']},
                   'expected': case['expected']}
        path = ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')
        path.write_text(json.dumps(fixture, indent=2) + '\n')
    bindings_path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(bindings_path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    for ident in IDS:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    bindings_path.write_text(json.dumps(bindings, indent=2) + '\n')
    print('Generated', len(cases), 'REG-02 cases and', len(controls), 'controls')


if __name__ == '__main__':
    main()
