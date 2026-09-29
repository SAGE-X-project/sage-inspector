"""Generate identity-preserving Guard replay and recovery sequences."""

import copy
import hashlib
import json
from pathlib import Path

import generate_guard_vectors as guard


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-05-N01', 'EXEC-05-N04', 'CST-01-01', 'CST-01-06')


def hash_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                               separators=(',', ':')).encode()).hexdigest()


def cases():
    historical = json.loads((ROOT / 'vectors/0.10.0/guard-records.json').read_text())
    valid = next(row['input'] for row in historical['cases'] if row['id'] == 'intent-valid')
    original = bytes.fromhex(valid['envelope_hex'])
    assert guard.jcs(guard.ENVELOPE) == original
    intent = guard.ENVELOPE['intent']
    changed_intent = copy.deepcopy(intent)
    changed_intent['nonce'] = guard.b64(bytes(range(1, 17)))
    changed_nonce = guard.jcs(guard.sign('intent', changed_intent)).hex()
    changed_proof = copy.deepcopy(guard.ENVELOPE)
    proof = changed_proof['proof']
    changed_proof['proof'] = ('A' if proof[0] != 'A' else 'B') + proof[1:]
    changed_proof_hex = guard.jcs(changed_proof).hex()
    intent_digest = hashlib.sha256(original).hexdigest()
    effect = {'instance': 'old', 'envelope_hex': original.hex(),
              'arguments_hex': guard.jcs(intent['arguments']).hex(),
              'tool': intent['tool'], 'manifest_digest': intent['manifest_digest'],
              'intent_digest': intent_digest}
    effect_hash = hash_json(effect)
    blank = {'ok': True, 'created': False, 'committed': False,
             'state': '', 'intent_digest': '', 'effect_sha256': []}
    accepted = {'ok': True, 'created': True, 'committed': True,
                'state': 'EXECUTING', 'intent_digest': intent_digest,
                'effect_sha256': [effect_hash]}
    denied = dict(blank, ok=False, effect_sha256=[effect_hash])
    duplicate = dict(blank, state='EXECUTING', intent_digest=intent_digest,
                     effect_sha256=[effect_hash])
    unknown = dict(blank, state='UNKNOWN', intent_digest=intent_digest)
    configure = {'action': 'configure', 'input': valid, 'instance': 'old'}
    dispatch = {'action': 'dispatch', 'envelope_hex': original.hex()}

    def stage(mode, *actions):
        return {'mode': mode, 'actions': list(actions)}

    return [
        ('EXEC-05-N01', [stage('create', configure, dispatch,
                                 {'action': 'dispatch', 'envelope_hex': changed_nonce})],
         {'verdict': 'REJECT',
          'output': {'stages': [[blank, accepted, denied]],
                     'journal_states': ['RESERVED', 'EXECUTING']},
          'effects': {'dispatch': 1}}),
        ('EXEC-05-N04', [stage('create', configure, dispatch),
                           stage('reopen', configure, dispatch, dispatch)],
         {'verdict': 'ACCEPT',
          'output': {'stages': [[blank, accepted], [blank, unknown, unknown]],
                     'journal_states': ['RESERVED', 'EXECUTING', 'UNKNOWN']},
          'effects': {'dispatch': 1}}),
        ('CST-01-01', [stage('create', configure, dispatch, dispatch)],
         {'verdict': 'ACCEPT',
          'output': {'stages': [[blank, accepted, duplicate]],
                     'journal_states': ['RESERVED', 'EXECUTING']},
          'effects': {'dispatch': 1}}),
        ('CST-01-06', [stage('create', configure, dispatch,
                               {'action': 'dispatch', 'envelope_hex': changed_proof_hex})],
         {'verdict': 'REJECT',
          'output': {'stages': [[blank, accepted, denied]],
                     'journal_states': ['RESERVED', 'EXECUTING']},
          'effects': {'dispatch': 1}}),
    ]


def main():
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'historical_bytes_sha256': '68bd8c57a9a572849ea5f57f77d93c0e7d2fe813ea7b158c47b24c832efdef0f',
             'scope': 'inert local ledger replay only; no distributed replica, real tool effect, cancellation, or authorization inheritance claim',
             'cases': []}
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident, stages, expected in cases():
        inp = {'operation': 'sage.guard.dispatch.sequence',
               'input': {'stages': stages}}
        suite['cases'].append({'id': ident, 'input': inp, 'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime', 'input': inp, 'expected': expected}
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'runtime',
                                     'fixture': relative,
                                     'fixture_sha256': hashlib.sha256(raw).hexdigest(),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec05-replay.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
