"""Generate exact-byte capture and approved-policy commitment probes."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-02-P', 'EXEC-02-N01', 'CST-02-01', 'CST-02-02')


def capture(items):
    wire = b'sage-original|0.10.0\x00' + len(items).to_bytes(4, 'big')
    for item in items:
        value = bytes.fromhex(item['hex'])
        wire += len(value).to_bytes(8, 'big') + value
    return hashlib.sha256(wire).hexdigest()


def policy(descriptor):
    canonical = json.dumps(descriptor, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False).encode()
    return hashlib.sha256(b'sage-policy|0.10.0\x00' + canonical).hexdigest()


def cases():
    capture_control = {'items': [{'hex': '52656164207468652066696c65'}]}
    capture_mutated = {'items': [{'hex': '52656164207468652066696c6520'}]}
    descriptor = {
        'version': '0.10.0',
        'issuer': 'did:sage:web:agents.example.com:alice',
        'epoch': '8f0264a0-8743-424a-b3d7-47090d31fca1',
        'engine': 'fixture-evaluator/1',
        'artifacts': {'version': '0.10.0', 'files': [
            {'path': 'policy/evaluator.wasm', 'sha256': '1' * 64},
            {'path': 'policy/rules.json', 'sha256': '2' * 64},
        ]},
    }
    altered = copy.deepcopy(descriptor)
    altered['artifacts']['files'][1]['sha256'] = '3' * 64
    return [
        ('EXEC-02-P', 'sage.guard.original.commit', capture_control,
         {'verdict': 'ACCEPT', 'output': {'original_digest': capture(capture_control['items'])},
          'effects': {}}),
        ('EXEC-02-N01', 'guard.original.pair',
         {'control': capture_control, 'candidate': capture_mutated},
         {'verdict': 'ACCEPT', 'output': {
             'control_digest': capture(capture_control['items']),
             'candidate_digest': capture(capture_mutated['items'])}, 'effects': {}}),
        ('CST-02-01', 'sage.guard.policy.commit', {'descriptor': descriptor},
         {'verdict': 'ACCEPT', 'output': {'policy_digest': policy(descriptor)},
          'effects': {}}),
        ('CST-02-02', 'guard.policy.pair',
         {'control': {'descriptor': descriptor},
          'candidate': {'descriptor': altered}},
         {'verdict': 'ACCEPT', 'output': {
             'control_digest': policy(descriptor),
             'candidate_digest': policy(altered)}, 'effects': {}}),
    ]


def main():
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'scope': 'capture and policy hash primitives only; no trusted capture, authorization, retirement, or delegation claim',
             'cases': []}
    bindings_path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(bindings_path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident, operation, inp, expected in cases():
        suite['cases'].append({'id': ident, 'operation': operation,
                               'input': inp, 'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime', 'input': {'operation': operation, 'input': inp},
                   'expected': expected}
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'runtime',
                                     'fixture': relative,
                                     'fixture_sha256': hashlib.sha256(raw).hexdigest(),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec02-primitives.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    bindings_path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
