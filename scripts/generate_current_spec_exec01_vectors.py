"""Generate bounded Execution Guard trust-boundary review examples."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-01-P', 'EXEC-01-N01', 'EXEC-01-N02',
       'EXEC-01-N03', 'EXEC-01-N04')
PATHS = ('subprocess', 'network', 'file', 'retry', 'parallel', 'subagent')
ASSETS = ('original_request', 'policy', 'signing_key', 'component_manifest',
          'verifier', 'dispatch_gate')


def cases():
    good = {
        'untrusted_principals': ['plugin', 'skill', 'mcp', 'model', 'child'],
        'protected_assets': {
            asset: {'readers': ['trusted_client'], 'writers': ['trusted_admin']}
            for asset in ASSETS
        },
        'effect_paths': {path: {'mediated_by': 'trusted_dispatch_gate',
                                'bypass_credentials_exposed': False}
                         for path in PATHS},
        'hook': {'mandatory': True, 'writers': ['trusted_admin']},
        'server': {'verifier_boundary': 'trusted_server',
                   'dispatcher_boundary': 'trusted_server',
                   'tool_boundary': 'isolated_untrusted',
                   'tool_has_host_privilege': False},
    }
    rows = [('EXEC-01-P', good, 'ACCEPT')]
    plugin_key = copy.deepcopy(good)
    plugin_key['protected_assets']['signing_key']['readers'].append('plugin')
    rows.append(('EXEC-01-N01', plugin_key, 'REJECT'))
    replaced_verifier = copy.deepcopy(good)
    replaced_verifier['protected_assets']['verifier']['writers'].append('plugin')
    rows.append(('EXEC-01-N02', replaced_verifier, 'REJECT'))
    bypass = copy.deepcopy(good)
    bypass['effect_paths']['subprocess']['mediated_by'] = 'untrusted_plugin'
    rows.append(('EXEC-01-N03', bypass, 'REJECT'))
    disabled = copy.deepcopy(good)
    disabled['hook']['mandatory'] = False
    rows.append(('EXEC-01-N04', disabled, 'REJECT'))
    return rows


def main():
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source': 'profiles/agent-mcp-security.md#1-protection-and-trust-boundary--exec-01',
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'scope': 'synthetic capability description only; no host isolation or deployment conformance claim',
             'cases': []}
    base = ROOT / 'vectors/0.10.0/current-spec'
    bindings_path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(bindings_path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    for ident, inp, verdict in cases():
        expected = {'verdict': verdict, 'output': {}, 'effects': {}}
        suite['cases'].append({'id': ident, 'input': inp, 'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'deployment_review',
                   'input': {'review_type': 'execution_guard_capability_boundary',
                             'synthetic_description': inp}, 'expected': expected}
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'deployment_review',
                                     'fixture': relative,
                                     'fixture_sha256': hashlib.sha256(raw).hexdigest(),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec01-review-scenarios.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    bindings_path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
