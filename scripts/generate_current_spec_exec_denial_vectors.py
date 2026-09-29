"""Bind policy, resolver and retirement denials to live dispatch fixtures."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-04-N01', 'EXEC-04-N02', 'CST-02-03')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    historical = json.loads((ROOT / 'vectors/0.10.0/guard-records.json').read_text())
    valid = next(row['input'] for row in historical['cases'] if row['id'] == 'intent-valid')
    blank = {'ok': True, 'created': False, 'committed': False,
             'state': '', 'intent_digest': '', 'effect_sha256': []}
    denied = dict(blank, ok=False)
    call = {'action': 'dispatch', 'envelope_hex': valid['envelope_hex']}
    out = []
    for ident, key in ((IDS[0], 'policy_allow'), (IDS[1], 'active_key')):
        invalid = copy.deepcopy(valid)
        invalid[key] = False
        actions = [{'action': 'configure', 'input': invalid,
                    'instance': 'old'}, call]
        out.append((ident, actions, [blank, denied]))
    retired = [{'action': 'configure', 'input': valid,
                'instance': 'old'}, {'action': 'retire'}, call]
    out.append((IDS[2], retired, [blank, blank, denied]))
    return [(ident, {'operation': 'sage.guard.dispatch.sequence',
                     'input': {'stages': [{'mode': 'create',
                                          'actions': actions}]}},
             {'verdict': 'REJECT',
              'output': {'stages': [expected], 'journal_states': []},
              'effects': {'dispatch': 0}})
            for ident, actions, expected in out]


def main():
    source = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(source.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'historical_bytes_sha256': sha((ROOT / 'vectors/0.10.0/guard-records.json').read_bytes()),
             'scope': 'local resolver, policy and retirement controls with inert dispatch only; no deployment-wide race or host-isolation claim',
             'cases': []}
    for ident, inp, expected in cases():
        suite['cases'].append({'id': ident, 'input': inp, 'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'runtime',
                   'input': inp, 'expected': expected}
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / path).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'runtime',
                                     'fixture': path, 'fixture_sha256': sha(raw),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec-denials.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    source.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
