"""Generate bounded signed-result lifecycle and durable race probes."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('CST-01-02', 'CST-01-09', 'CST-01-10')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def cases():
    historical = {row['id']: row for row in json.loads(
        (ROOT / 'vectors/0.10.0/guard-records.json').read_text())['cases']}
    f = historical['intent-valid']['input']
    public = historical['result-completed-valid']['input']['public_key_hex']
    envelope = bytes.fromhex(f['envelope_hex'])
    intent = json.loads(envelope)['intent']
    intent_sha = sha(envelope)
    effect = {'instance': 'old', 'envelope_hex': envelope.hex(),
              'arguments_hex': jcs(intent['arguments']).hex(),
              'tool': intent['tool'], 'manifest_digest': intent['manifest_digest'],
              'intent_digest': intent_sha}
    effect_sha = sha(jcs(effect))

    def row(*, ok=True, created=False, committed=False, state='',
            digest='', signs=0, status='', signed=False, effect=False):
        return {'ok': ok, 'created': created, 'committed': committed,
                'state': state, 'intent_digest': digest, 'signs': signs,
                'result_status': status, 'result_signature_valid': signed,
                'effect_sha256': [effect_sha] if effect else []}

    blank = row()
    dispatch = row(created=True, committed=True, state='EXECUTING',
                   digest=intent_sha, effect=True)
    configure = {'action': 'configure', 'input': f, 'instance': 'old'}
    call = {'action': 'dispatch', 'envelope_hex': envelope.hex()}
    reply = {'action': 'reply'}
    finish = {'action': 'finish', 'output': {'value': 'ok'}}
    journal = ['RESERVED', 'EXECUTING', 'COMPLETED']
    common = {'journal_states': journal,
              'stored_result_status': 'completed',
              'stored_result_signature_valid': True}
    return [
        ('CST-01-02', [configure, call, reply, finish, reply, call, reply],
         {'verdict': 'ACCEPT', 'output': dict(common,
             rows=[blank, dispatch,
                   row(signs=1, status='pending', signed=True, effect=True),
                   row(signs=2, effect=True),
                   row(ok=False, signs=2, effect=True),
                   row(state='COMPLETED', digest=intent_sha, signs=2,
                       effect=True),
                   row(signs=2, status='completed', signed=True, effect=True)],
             published_terminal_matches_storage=True),
          'effects': {'dispatch': 1}}),
        ('CST-01-09', [configure, call,
                       {'action': 'reject', 'envelope_hex': envelope.hex()},
                       finish, reply],
         {'verdict': 'ACCEPT', 'output': dict(common,
             rows=[blank, dispatch, row(ok=False, effect=True),
                   row(signs=1, effect=True),
                   row(signs=1, status='completed', signed=True, effect=True)],
             published_terminal_matches_storage=True),
          'effects': {'dispatch': 1}}),
        ('CST-01-10', [configure, call, finish,
                       {'action': 'signer', 'now': intent['expires'],
                        'active': True}, reply],
         {'verdict': 'REJECT', 'output': dict(common,
             rows=[blank, dispatch, row(signs=1, effect=True),
                   row(signs=1, effect=True),
                   row(ok=False, signs=1, effect=True)],
             published_terminal_matches_storage=False),
          'effects': {'dispatch': 1}}),
    ], public


def main():
    rows, public = cases()
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'historical_bytes_sha256': '68bd8c57a9a572849ea5f57f77d93c0e7d2fe813ea7b158c47b24c832efdef0f',
             'scope': 'signed executor snapshots and local durable ledger only; no client model consumption or deployed external effect claim',
             'cases': []}
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident, actions, expected in rows:
        inp = {'operation': 'sage.guard.result.sequence',
               'input': {'actions': actions, 'public_key_hex': public}}
        suite['cases'].append({'id': ident, 'input': inp, 'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime', 'input': inp, 'expected': expected}
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'runtime',
                                     'fixture': relative,
                                     'fixture_sha256': sha(raw),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec-result-state.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
