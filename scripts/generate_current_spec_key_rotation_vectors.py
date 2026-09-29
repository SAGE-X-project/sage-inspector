"""Bind local replay refusal after current key authority changes."""

import copy
import hashlib
import json
from pathlib import Path

from generate_current_spec_exec05_replay_vectors import cases as replay_cases


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
ID = 'EXEC-05-N02'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def case():
    _, original_stages, original_expected = next(
        row for row in replay_cases() if row[0] == 'EXEC-05-N04')
    stages = copy.deepcopy(original_stages)
    stages[1]['actions'][0] = copy.deepcopy(stages[1]['actions'][0])
    stages[1]['actions'][0]['input'] = copy.deepcopy(
        stages[1]['actions'][0]['input'])
    stages[1]['actions'][0]['input']['active_key'] = False
    stages[1]['actions'].pop()
    blank = {'ok': True, 'created': False, 'committed': False,
             'state': '', 'intent_digest': '', 'effect_sha256': []}
    expected = {'verdict': 'REJECT',
                'output': {'stages': [original_expected['output']['stages'][0],
                                      [blank, dict(blank, ok=False)]],
                           'journal_states': ['RESERVED', 'EXECUTING', 'UNKNOWN']},
                'effects': {'dispatch': 1}}
    return {'operation': 'sage.guard.dispatch.sequence',
            'input': {'stages': stages}}, expected


def main():
    inp, expected = case()
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] != ID]
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'source_bytes_sha256': sha((ROOT / 'vectors/0.10.0/guard-records.json').read_bytes()),
             'scope': 'inert local ledger replay and changed active key only; no distributed transport or deployed rotation authority',
             'case': {'id': ID, 'input': inp, 'expected': expected}}
    relative = f'vectors/0.10.0/current-spec/{ID}.json'
    raw = (json.dumps({'schema_version': 1, 'spec_revision': SPEC,
                       'id': ID, 'track': 'runtime', 'input': inp,
                       'expected': expected}, indent=2) + '\n').encode()
    (ROOT / relative).write_bytes(raw)
    bindings['bindings'].append({'id': ID, 'track': 'runtime',
                                 'fixture': relative,
                                 'fixture_sha256': sha(raw),
                                 'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec-key-rotation.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
