"""Generate bounded real-core dispatch and recovery sequences."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-04-P', 'EXEC-04-N03', 'EXEC-04-N05', 'EXEC-05-P')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                               separators=(',', ':')).encode()).hexdigest()


def cases():
    historical = json.loads((ROOT / 'vectors/0.10.0/guard-records.json').read_text())
    valid = next(row['input'] for row in historical['cases'] if row['id'] == 'intent-valid')
    raw = bytes.fromhex(valid['envelope_hex'])
    intent = json.loads(raw)['intent']
    intent_digest = hashlib.sha256(raw).hexdigest()
    effect = {'instance': 'old', 'envelope_hex': raw.hex(),
              'arguments_hex': json.dumps(intent['arguments'], sort_keys=True,
                                          separators=(',', ':')).encode().hex(),
              'tool': intent['tool'], 'manifest_digest': intent['manifest_digest'],
              'intent_digest': intent_digest}
    effect_hash = digest(effect)
    blank = {'ok': True, 'created': False, 'committed': False,
             'state': '', 'intent_digest': '', 'effect_sha256': []}
    accepted = {'ok': True, 'created': True, 'committed': True,
                'state': 'EXECUTING', 'intent_digest': intent_digest,
                'effect_sha256': [effect_hash]}
    denied = dict(blank, ok=False)
    unknown = dict(blank, state='UNKNOWN', intent_digest=intent_digest)
    dispatch = {'action': 'dispatch', 'envelope_hex': valid['envelope_hex']}

    def stage(mode, fixture):
        return {'mode': mode, 'actions': [
            {'action': 'configure', 'input': fixture, 'instance': 'old'}, dispatch]}

    mismatch = copy.deepcopy(valid)
    mismatch['approved_manifest']['files'][0]['sha256'] = '0' * 64
    expired = copy.deepcopy(valid)
    expired['now'] = intent['expires']
    return [
        ('EXEC-04-P', [stage('create', valid)],
         {'verdict': 'ACCEPT',
          'output': {'stages': [[blank, accepted]],
                     'journal_states': ['RESERVED', 'EXECUTING']},
          'effects': {'dispatch': 1}}),
        ('EXEC-04-N03', [stage('create', mismatch)],
         {'verdict': 'REJECT', 'output': {'stages': [[blank, denied]],
                                       'journal_states': []},
          'effects': {'dispatch': 0}}),
        ('EXEC-04-N05', [stage('create', expired)],
         {'verdict': 'REJECT', 'output': {'stages': [[blank, denied]],
                                       'journal_states': []},
          'effects': {'dispatch': 0}}),
        ('EXEC-05-P', [stage('create', valid), stage('reopen', valid)],
         {'verdict': 'ACCEPT',
          'output': {'stages': [[blank, accepted], [blank, unknown]],
                     'journal_states': ['RESERVED', 'EXECUTING', 'UNKNOWN']},
          'effects': {'dispatch': 1}}),
    ]


def main():
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'historical_bytes_sha256': '68bd8c57a9a572849ea5f57f77d93c0e7d2fe813ea7b158c47b24c832efdef0f',
             'scope': 'inert fixture sink and durable local ledger only; no deployed tool, trusted loader, or host isolation claim',
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
    (ROOT / 'vectors/0.10.0/exec04-dispatch.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
