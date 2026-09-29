"""Independently audit pending, rejection-race, and expired-result sequences."""

import hashlib
import json

from current_spec_catalog import ROOT, load, require, sha


SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('CST-01-02', 'CST-01-09', 'CST-01-10')
SOURCE = 'vectors/0.10.0/exec-result-state.json'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == manifest['source_sha256'][
                'profiles/agent-mcp-security.md'] and
            suite['historical_bytes_sha256'] ==
            sha((root / 'vectors/0.10.0/guard-records.json').read_bytes()) ==
            '68bd8c57a9a572849ea5f57f77d93c0e7d2fe813ea7b158c47b24c832efdef0f' and
            suite['scope'] == 'signed executor snapshots and local durable ledger only; no client model consumption or deployed external effect claim' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'result lifecycle source and case identity')
    inputs = [row['input']['input'] for row in suite['cases']]
    first = inputs[0]['actions']
    require([row['action'] for row in first] == [
            'configure', 'dispatch', 'reply', 'finish', 'reply', 'dispatch', 'reply'] and
            [row['action'] for row in inputs[1]['actions']] == [
                'configure', 'dispatch', 'reject', 'finish', 'reply'] and
            [row['action'] for row in inputs[2]['actions']] == [
                'configure', 'dispatch', 'finish', 'signer', 'reply'] and
            all(row['actions'][0] == first[0] and
                row['actions'][1] == first[1] and
                row['public_key_hex'] == inputs[0]['public_key_hex']
                for row in inputs),
            'single controlled pending, rejection race, and expiry changes')
    raw = bytes.fromhex(first[0]['input']['envelope_hex'])
    intent = load(raw)['intent']
    require(first[1]['envelope_hex'] == raw.hex() and
            first[5] == first[1] and
            inputs[1]['actions'][2]['envelope_hex'] == raw.hex() and
            inputs[2]['actions'][3]['now'] == intent['expires'],
            'exact duplicate and exclusive terminal expiry')
    intent_sha = hashlib.sha256(raw).hexdigest()
    effect = {'instance': 'old', 'envelope_hex': raw.hex(),
              'arguments_hex': json.dumps(intent['arguments'], sort_keys=True,
                                          separators=(',', ':')).encode().hex(),
              'tool': intent['tool'], 'manifest_digest': intent['manifest_digest'],
              'intent_digest': intent_sha}
    effect_sha = hashlib.sha256(json.dumps(effect, sort_keys=True,
                                            separators=(',', ':')).encode()).hexdigest()
    for index, case in enumerate(suite['cases']):
        ident = IDS[index]
        outcome = case['expected']
        rows = outcome['output']['rows']
        require(outcome['verdict'] == ('REJECT' if index == 2 else 'ACCEPT') and
                outcome['effects'] == {'dispatch': 1} and
                outcome['output']['journal_states'] ==
                ['RESERVED', 'EXECUTING', 'COMPLETED'] and
                outcome['output']['stored_result_status'] == 'completed' and
                outcome['output']['stored_result_signature_valid'] is True and
                outcome['output']['published_terminal_matches_storage'] is
                (index != 2) and
                len(rows) == len(inputs[index]['actions']) and
                rows[0]['effect_sha256'] == [] and
                all(row['effect_sha256'] == [effect_sha] for row in rows[1:]) and
                rows[1]['committed'] is True and
                rows[1]['intent_digest'] == intent_sha,
                'one exact inert effect and stored signed terminal: ' + ident)
    pending = suite['cases'][0]['expected']['output']['rows']
    race = suite['cases'][1]['expected']['output']['rows']
    expiry = suite['cases'][2]['expected']['output']['rows']
    require((pending[2]['result_status'], pending[2]['signs'],
             pending[2]['result_signature_valid']) == ('pending', 1, True) and
            (pending[4]['ok'], pending[4]['signs']) == (False, 2) and
            (pending[6]['result_status'], pending[6]['signs'],
             pending[6]['result_signature_valid']) == ('completed', 2, True) and
            race[2]['ok'] is False and race[4]['result_status'] == 'completed' and
            expiry[4]['ok'] is False and expiry[4]['result_status'] == '',
            'pending snapshot, conflicting rejection, and expired retrieval')
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    for case in suite['cases']:
        ident = case['id']
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': case['input'], 'expected': case['expected']},
                'result lifecycle fixture contract: ' + ident)
        require(any(binding == {'id': ident, 'track': 'runtime',
                                'fixture': path,
                                'fixture_sha256': sha((root / path).read_bytes()),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'result lifecycle partial binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
