"""Independently check current client result-consumption case fixtures."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from current_spec_catalog import ROOT, load, require, sha
from generate_current_spec_exec_client_vectors import SCENARIOS, SPEC


SOURCE = 'vectors/0.10.0/exec-client-consumption.json'
HISTORICAL = '2c7b043f6f761a2eff0e7eea89cf838746a31a221c31e2d82b47d30b6937c271'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    historical = load((root / 'vectors/0.10.0/guard-client.json').read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] ==
            manifest['source_sha256']['profiles/agent-mcp-security.md'] and
            suite['historical_bytes_sha256'] == HISTORICAL ==
            sha((root / 'vectors/0.10.0/guard-client.json').read_bytes()) and
            tuple(row['id'] for row in suite['cases']) == tuple(SCENARIOS) and
            suite['scope'] ==
            'bounded client consumption and local durable journal only; no model decision or deployed transport claim',
            'pinned client source and case identities')
    prior = {row['id']: row for row in historical['cases']}
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    public = bytes.fromhex(historical['public_key_hex'])
    intent = bytes.fromhex(historical['input']['envelope_hex'])
    intent_digest = hashlib.sha256(intent).hexdigest()
    for case in suite['cases']:
        ident = case['id']
        source = case['input']['input']
        expected = case['expected']
        require(case['input']['operation'] == 'sage.guard.client.sequence' and
                source['configuration'] == historical['input'] and
                source['public_key_hex'] == historical['public_key_hex'] and
                source['results'] == historical['results'] and
                tuple(row['name'] for row in source['scenarios']) ==
                SCENARIOS[ident] and expected['verdict'] == 'ACCEPT' and
                expected['effects']['handoff'] in (2, 3),
                'client input and scenario identity: ' + ident)
        for scenario in source['scenarios']:
            name = scenario['name']
            original = prior[name]
            require(scenario['steps'] == [
                        {key: value for key, value in row.items()
                         if key != 'expected'} for row in original['steps']] and
                    all('expected' not in row for row in scenario['steps']),
                    'answer excluded from adapter input: ' + ident)
            observed = expected['output']['scenarios'][name]
            require([row['ok'] for row in observed['steps']] ==
                    [True] + [step['expected']['ok'] for step in original['steps']] and
                    [row['handoffs'] for row in observed['steps']] ==
                    [0] + [step['expected']['handoffs'] for step in original['steps']] and
                    observed['intent_unchanged'] is True and
                    observed['signed_results_valid'] is True and
                    observed['terminal_results'] ==
                    (0 if name == 'expired-result' else 1),
                    'client expected observations: ' + ident)
            for step in scenario['steps']:
                if step['action'] != 'accept':
                    continue
                envelope = json.loads(bytes.fromhex(
                    source['results'][step['result']]))
                result = envelope['result']
                proof = base64.urlsafe_b64decode(envelope['proof'] + '=' *
                                                 (-len(envelope['proof']) % 4))
                Ed25519PublicKey.from_public_bytes(public).verify(
                    proof, b'sage-tool-result|0.10.0\x00' +
                    json.dumps(result, sort_keys=True,
                               separators=(',', ':')).encode())
                require(result['intent_digest'] == intent_digest,
                        'result bound to exact intent: ' + ident)
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': case['input'], 'expected': expected} and
                any(row == {'id': ident, 'track': 'runtime',
                            'fixture': path,
                            'fixture_sha256': sha((root / path).read_bytes()),
                            'coverage': 'partial'}
                    for row in bindings['bindings']),
                'current client fixture binding: ' + ident)
    duplicate = suite['cases'][0]['expected']['output']['scenarios'][
        'late-pending-and-duplicate']['steps']
    conflict = suite['cases'][2]['expected']['output']['scenarios'][
        'conflicting-terminal']['steps']
    poll = suite['cases'][3]['expected']['output']['scenarios'][
        'poll-boundary']['steps']
    expiry = suite['cases'][3]['expected']['output']['scenarios'][
        'expired-result']['steps']
    require(duplicate[6]['first'] and duplicate[7]['ignored'] and
            duplicate[8]['ignored'] and not duplicate[9]['ok'] and
            conflict[4]['first'] and not conflict[5]['ok'] and
            not conflict[6]['ok'] and
            not poll[3]['ok'] and poll[5]['handoffs'] == 2 and
            poll[6]['status'] == 'pending' and poll[7]['first'] and
            not expiry[3]['ok'] and not expiry[4]['ok'],
            'duplicate, delayed pending, conflict, polling and expiry boundaries')
    return len(SCENARIOS)


if __name__ == '__main__':
    print(check())
