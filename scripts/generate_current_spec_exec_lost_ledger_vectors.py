"""Bind missing durable dispatch state to fail-closed case fixtures."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-05-N03', 'CST-02-04')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    historical = json.loads((ROOT / 'vectors/0.10.0/guard-records.json').read_text())
    valid = next(row['input'] for row in historical['cases'] if row['id'] == 'intent-valid')
    inp = {'operation': 'sage.guard.dispatch.missing-ledger',
           'input': {'configuration': valid,
                     'envelope_hex': valid['envelope_hex']}}
    expected = {'verdict': 'REJECT',
                'output': {'before_states': ['RESERVED', 'EXECUTING'],
                           'reopen_exit': 2, 'reopen_stdout_empty': True,
                           'journal_recreated': False,
                           'retained_history_unchanged': True,
                           'post_loss_effects': 0},
                'effects': {'dispatch_before_loss': 1,
                            'dispatch_after_loss': 0}}
    return [(ident, inp, expected) for ident in IDS]


def main():
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'historical_bytes_sha256': sha((ROOT / 'vectors/0.10.0/guard-records.json').read_bytes()),
             'scope': 'single local Guard ledger absence after a committed inert handoff; no trusted epoch recovery or distributed reconciliation claim',
             'cases': []}
    for ident, inp, expected in cases():
        suite['cases'].append({'id': ident, 'input': inp, 'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'runtime',
                   'input': inp, 'expected': expected}
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'runtime',
                                     'fixture': relative,
                                     'fixture_sha256': sha(raw),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec-lost-ledger.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
