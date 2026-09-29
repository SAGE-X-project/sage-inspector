"""Bind client result-consumption scenarios to current EXEC cases."""

import hashlib
import json
from pathlib import Path

from test_guard_client010 import case_commands


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
SCENARIOS = {
    'EXEC-07-N04': ('late-pending-and-duplicate',),
    'CST-01-03': ('late-pending-and-duplicate',),
    'CST-01-04': ('conflicting-terminal',),
    'CST-01-08': ('poll-boundary', 'expired-result'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def summary(wants, journal):
    return {
        'steps': [{key: row[key] for key in
                   ('ok', 'status', 'first', 'ignored', 'handoffs')}
                  for row in wants],
        'journal_kinds': [row['kind'] for row in journal],
        'terminal_results': sum(row['kind'] == 'terminal' for row in journal),
        'intent_unchanged': True,
        'signed_results_valid': True,
    }


def cases():
    source = json.loads((ROOT / 'vectors/0.10.0/guard-client.json').read_text())
    historical = {case['id']: case for case in source['cases']}
    out = []
    for ident, names in SCENARIOS.items():
        scenarios = []
        expected = {}
        for name in names:
            commands, wants, journal = case_commands(source, historical[name])
            steps = []
            for step in historical[name]['steps']:
                steps.append({key: value for key, value in step.items()
                              if key != 'expected'})
            scenarios.append({'name': name, 'steps': steps})
            expected[name] = summary(wants, journal)
        inp = {'operation': 'sage.guard.client.sequence', 'input': {
            'configuration': source['input'],
            'public_key_hex': source['public_key_hex'],
            'results': source['results'], 'scenarios': scenarios}}
        out.append((ident, inp, {'verdict': 'ACCEPT',
                                 'output': {'scenarios': expected},
                                 'effects': {'handoff': max(
                                     max(row['handoffs'] for row in value['steps'])
                                     for value in expected.values())}}))
    return out


def main():
    bindings_path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(bindings_path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in SCENARIOS]
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'historical_bytes_sha256': sha((ROOT / 'vectors/0.10.0/guard-client.json').read_bytes()),
             'scope': 'bounded client consumption and local durable journal only; no model decision or deployed transport claim',
             'cases': []}
    for ident, inp, expected in cases():
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
    (ROOT / 'vectors/0.10.0/exec-client-consumption.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    bindings_path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
