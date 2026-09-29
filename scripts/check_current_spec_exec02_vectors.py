"""Independently audit exact capture and policy commitment fixtures."""

import copy
import hashlib
import json

from current_spec_catalog import ROOT, load, require, sha


SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-02-P', 'EXEC-02-N01', 'CST-02-01', 'CST-02-02')
SOURCE = 'vectors/0.10.0/exec02-primitives.json'


def independent_capture(items):
    raw = bytearray(b'sage-original|0.10.0\x00')
    raw.extend(len(items).to_bytes(4, 'big'))
    for item in items:
        chunk = bytes.fromhex(item['hex'])
        raw.extend(len(chunk).to_bytes(8, 'big'))
        raw.extend(chunk)
    return hashlib.sha256(raw).hexdigest()


def independent_policy(descriptor):
    canonical = json.dumps(descriptor, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(b'sage-policy|0.10.0\x00' + canonical).hexdigest()


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == manifest['source_sha256'][
                'profiles/agent-mcp-security.md'] and
            suite['scope'] == 'capture and policy hash primitives only; no trusted capture, authorization, retirement, or delegation claim' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'EXEC-02 source and case identities')
    original, changed, policy, altered = [row['input'] for row in suite['cases']]
    require(original == {'items': [{'hex': '52656164207468652066696c65'}]} and
            changed['control'] == original and
            changed['candidate'] == {'items': [{'hex': '52656164207468652066696c6520'}]} and
            independent_capture(original['items']) !=
            independent_capture(changed['candidate']['items']),
            'exact original bytes and one-byte mutation')
    descriptor = policy['descriptor']
    require(set(descriptor) == {'version', 'issuer', 'epoch', 'engine', 'artifacts'} and
            descriptor['version'] == '0.10.0' and
            len(descriptor['artifacts']['files']) == 2 and
            altered['control'] == policy,
            'closed policy commitment input')
    mutation = copy.deepcopy(policy)
    mutation['descriptor']['artifacts']['files'][1]['sha256'] = '3' * 64
    require(altered['candidate'] == mutation and
            independent_policy(descriptor) !=
            independent_policy(mutation['descriptor']),
            'one artifact digest mutation')
    expected = (
        {'original_digest': independent_capture(original['items'])},
        {'control_digest': independent_capture(original['items']),
         'candidate_digest': independent_capture(changed['candidate']['items'])},
        {'policy_digest': independent_policy(descriptor)},
        {'control_digest': independent_policy(descriptor),
         'candidate_digest': independent_policy(mutation['descriptor'])},
    )
    operations = ('sage.guard.original.commit', 'guard.original.pair',
                  'sage.guard.policy.commit', 'guard.policy.pair')
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    for index, row in enumerate(suite['cases']):
        ident = IDS[index]
        outcome = {'verdict': 'ACCEPT', 'output': expected[index], 'effects': {}}
        path = 'vectors/0.10.0/current-spec/' + ident + '.json'
        fixture = load((root / path).read_bytes())
        require(row['operation'] == operations[index] and
                row['expected'] == outcome and fixture == {
                    'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                    'track': 'runtime',
                    'input': {'operation': operations[index], 'input': row['input']},
                    'expected': outcome}, 'EXEC-02 fixture contract: ' + ident)
        require(any(binding == {'id': ident, 'track': 'runtime',
                                'fixture': path,
                                'fixture_sha256': sha((root / path).read_bytes()),
                                'coverage': 'partial'}
                    for binding in bindings['bindings']),
                'EXEC-02 partial runtime binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
