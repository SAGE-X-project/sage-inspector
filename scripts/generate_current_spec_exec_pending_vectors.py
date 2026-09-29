"""Bind distinct Client UNKNOWN and MCP pending observations."""

import hashlib
import json
from pathlib import Path

from generate_current_spec_exec_client_vectors import summary
from test_guard_client010 import case_commands


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('CST-01-05', 'CST-01-07')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    client = json.loads((ROOT / 'vectors/0.10.0/guard-client.json').read_text())
    historical = {row['id']: row for row in client['cases']}
    names = ('poll-boundary', 'unknown')
    scenarios = []
    expected_scenarios = {}
    for name in names:
        commands, wants, journal = case_commands(client, historical[name])
        scenarios.append({'name': name, 'steps': [
            {key: value for key, value in step.items() if key != 'expected'}
            for step in historical[name]['steps']]})
        expected_scenarios[name] = summary(wants, journal)
    client_input = {'operation': 'sage.guard.client.sequence', 'input': {
        'configuration': client['input'],
        'public_key_hex': client['public_key_hex'],
        'results': client['results'], 'scenarios': scenarios}}
    client_expected = {'verdict': 'ACCEPT',
                       'output': {'scenarios': expected_scenarios},
                       'effects': {'handoff': 2}}
    mcp = {row['id']: row for row in json.loads(
        (ROOT / 'vectors/0.10.0/guard-mcp.json').read_text())['cases']}
    pending = mcp['pending']['input']
    mcp_input = {'operation': 'sage.guard.mcp.verify', 'input': pending}
    mcp_expected = {'verdict': 'ACCEPT',
                    'output': {'success': False, 'error': 'unavailable',
                               'status': 'pending',
                               'wire_hex': pending['wire_hex']},
                    'effects': {}}
    return [(IDS[0], client_input, client_expected),
            (IDS[1], mcp_input, mcp_expected)]


def main():
    binding_path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(binding_path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'client_bytes_sha256': sha((ROOT / 'vectors/0.10.0/guard-client.json').read_bytes()),
             'mcp_bytes_sha256': sha((ROOT / 'vectors/0.10.0/guard-mcp.json').read_bytes()),
             'scope': 'bounded local Client state and signed MCP representation only; no HTTP pending or deployed model-consumption claim',
             'cases': []}
    for ident, inp, expected in cases():
        suite['cases'].append({'id': ident, 'input': inp,
                               'expected': expected})
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
    (ROOT / 'vectors/0.10.0/exec-pending.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    binding_path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
