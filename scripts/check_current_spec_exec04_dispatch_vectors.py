"""Independently audit inert dispatch and durable recovery fixtures."""

import copy
import hashlib
import json

from current_spec_catalog import ROOT, load, require, sha


SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-04-P', 'EXEC-04-N03', 'EXEC-04-N05', 'EXEC-05-P')
SOURCE = 'vectors/0.10.0/exec04-dispatch.json'
HISTORICAL_SHA = '68bd8c57a9a572849ea5f57f77d93c0e7d2fe813ea7b158c47b24c832efdef0f'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == manifest['source_sha256'][
                'profiles/agent-mcp-security.md'] and
            suite['historical_bytes_sha256'] == HISTORICAL_SHA ==
            sha((root / 'vectors/0.10.0/guard-records.json').read_bytes()) and
            suite['scope'] == 'inert fixture sink and durable local ledger only; no deployed tool, trusted loader, or host isolation claim' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'EXEC-04/05 source and scope')
    good, mismatch, expired, recovery = [row['input']['input']['stages']
                                         for row in suite['cases']]
    require(len(good) == len(mismatch) == len(expired) == 1 and
            len(recovery) == 2 and recovery[0] == good[0] and
            recovery[1]['mode'] == 'reopen' and
            recovery[1]['actions'] == good[0]['actions'],
            'create and recovery sequence')
    config = good[0]['actions'][0]['input']
    raw = bytes.fromhex(config['envelope_hex'])
    intent = load(raw)['intent']
    require(good[0]['actions'][0]['action'] == 'configure' and
            good[0]['actions'][1] == {'action': 'dispatch',
                                      'envelope_hex': raw.hex()},
            'exact signed envelope dispatched')
    wrong_manifest = copy.deepcopy(config)
    wrong_manifest['approved_manifest']['files'][0]['sha256'] = '0' * 64
    old_time = copy.deepcopy(config)
    old_time['now'] = intent['expires']
    require(mismatch[0]['actions'][0]['input'] == wrong_manifest and
            expired[0]['actions'][0]['input'] == old_time and
            mismatch[0]['actions'][1] == good[0]['actions'][1] ==
            expired[0]['actions'][1],
            'single manifest or time mutation before dispatch')
    intent_digest = hashlib.sha256(raw).hexdigest()
    effect = {'instance': 'old', 'envelope_hex': raw.hex(),
              'arguments_hex': json.dumps(intent['arguments'], sort_keys=True,
                                          separators=(',', ':')).encode().hex(),
              'tool': intent['tool'], 'manifest_digest': intent['manifest_digest'],
              'intent_digest': intent_digest}
    effect_sha = hashlib.sha256(json.dumps(effect, sort_keys=True,
                                            separators=(',', ':')).encode()).hexdigest()
    blank = {'ok': True, 'created': False, 'committed': False,
             'state': '', 'intent_digest': '', 'effect_sha256': []}
    committed = {'ok': True, 'created': True, 'committed': True,
                 'state': 'EXECUTING', 'intent_digest': intent_digest,
                 'effect_sha256': [effect_sha]}
    denied = dict(blank, ok=False)
    unknown = dict(blank, state='UNKNOWN', intent_digest=intent_digest)
    outcomes = (
        {'verdict': 'ACCEPT', 'output': {'stages': [[blank, committed]],
                                      'journal_states': ['RESERVED', 'EXECUTING']},
         'effects': {'dispatch': 1}},
        {'verdict': 'REJECT', 'output': {'stages': [[blank, denied]],
                                      'journal_states': []},
         'effects': {'dispatch': 0}},
        {'verdict': 'REJECT', 'output': {'stages': [[blank, denied]],
                                      'journal_states': []},
         'effects': {'dispatch': 0}},
        {'verdict': 'ACCEPT', 'output': {
            'stages': [[blank, committed], [blank, unknown]],
            'journal_states': ['RESERVED', 'EXECUTING', 'UNKNOWN']},
         'effects': {'dispatch': 1}},
    )
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    for index, row in enumerate(suite['cases']):
        ident = IDS[index]
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(row['expected'] == outcomes[index] and fixture == {
            'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
            'track': 'runtime', 'input': row['input'],
            'expected': outcomes[index]} and
            row['input']['operation'] == 'sage.guard.dispatch.sequence',
            'EXEC-04/05 fixture contract: ' + ident)
        require(any(binding == {'id': ident, 'track': 'runtime',
                                'fixture': path,
                                'fixture_sha256': sha((root / path).read_bytes()),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'EXEC-04/05 partial runtime binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
