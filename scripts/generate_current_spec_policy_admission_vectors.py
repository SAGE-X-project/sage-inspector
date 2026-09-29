"""Bind signed intent denials without claiming host policy isolation."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CASES = (('EXEC-02-N03', 'intent-policy-deny'),
         ('CST-02-05', 'intent-policy-self-approved'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    source = json.loads((ROOT / 'vectors/0.10.0/guard-records.json').read_text())
    historical = {row['id']: row for row in source['cases']}
    for ident, name in CASES:
        yield ident, historical[name]['input'], {
            'verdict': 'REJECT', 'output': {}, 'effects': {}}


def main():
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in {ident for ident, _ in CASES}]
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'historical_bytes_sha256': sha((ROOT / 'vectors/0.10.0/guard-records.json').read_bytes()),
             'scope': 'signed intent verification only; host policy-store isolation and effect gates require separate observation',
             'cases': []}
    for ident, inp, expected in cases():
        payload = {'operation': 'sage.guard.intent.verify', 'input': inp}
        suite['cases'].append({'id': ident, 'input': payload,
                               'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime', 'input': payload, 'expected': expected}
        relative = f'vectors/0.10.0/current-spec/{ident}.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'runtime',
                                     'fixture': relative,
                                     'fixture_sha256': sha(raw),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec-policy-admission.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
