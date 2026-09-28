"""Independently audit DID resolution metadata and authorization separation."""

import copy
import json

from check_current_spec_resolve01_vectors import decision as projection_decision
from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/resolve03-scenarios.json'
REGISTRY_SOURCE = 'vectors/0.10.0/reg08-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CHAPTER_SHA = '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c'
IDS = ('RESOLVE-03-P', 'RESOLVE-03-N01', 'RESOLVE-03-N02', 'RESOLVE-03-N03')


def decision(inp):
    observations, candidate = inp['observations'], inp['candidate']
    if (not isinstance(observations, list) or len(observations) != 3 or
            not isinstance(candidate, dict) or
            set(candidate) != {'resolutions', 'protected_operation_gate'} or
            len(candidate['resolutions']) != 3 or
            len(candidate['protected_operation_gate']) != 3):
        return 'REJECT'
    for observation, result, gate in zip(
            observations, candidate['resolutions'], candidate['protected_operation_gate']):
        record = observation['record']
        if (not isinstance(record, dict) or
                record.get('state') not in ('active', 'created', 'deactivated') or
                observation['source_authenticated'] is not True or
                observation['observation_current'] is not True or
                type(observation['issued']) is not int or
                type(observation['observed_time']) is not int or
                not isinstance(observation['source'], str) or
                not observation['source'].isascii() or
                not 1 <= len(observation['source'].encode()) <= 2048):
            return 'REJECT'
        if (not isinstance(result, dict) or
                set(result) != {'didDocument', 'didDocumentMetadata',
                                'didResolutionMetadata'} or
                projection_decision(record, result['didDocument']) != 'ACCEPT'):
            return 'REJECT'
        metadata = result['didDocumentMetadata']
        if (not isinstance(metadata, dict) or
                set(metadata) != {'deactivated', 'versionId', 'sage'} or
                metadata['deactivated'] is not (record['state'] == 'deactivated') or
                metadata['versionId'] != record['version'] or
                metadata['sage'] != {
                    'state': record['state'], 'controller': record['controller'],
                    'observedAt': observation['issued'],
                    'source': observation['source'],
                    'observedTime': observation['observed_time']} or
                result['didResolutionMetadata'] !=
                    {'contentType': 'application/did+json'} or
                gate != ('DEFER' if record['state'] == 'active' else 'DENY') or
                len(json.dumps(result, separators=(',', ':')).encode()) > 262144):
            return 'REJECT'
    return 'ACCEPT'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    raw = (root / REGISTRY_SOURCE).read_bytes()
    base = load(raw)['cases'][0]['input']
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == CHAPTER_SHA and
            manifest['source_sha256']['spec/10-resolution.md'] == CHAPTER_SHA and
            suite['registry_source_sha256'] == sha(raw) and
            suite['scope'] == 'synthetic current observations; no live Registry authentication, proof verification, or protected dispatch' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'pinned RESOLVE-03 sources and scope')
    positive = suite['cases'][0]
    inp, output = positive['input'], positive['expected']['output']
    states = ('active', 'created', 'deactivated')
    require(tuple(row['record']['state'] for row in inp['observations']) == states and
            all(row['record'] == dict(base['response']['body']['record'], state=state)
                and row['issued'] == base['response']['body']['issued']
                and row['observed_time'] == base['trusted_now']
                and row['source'] == base['policy']['configured_origin']
                for row, state in zip(inp['observations'], states)) and
            output == inp['candidate'] and
            output['protected_operation_gate'] == ['DEFER', 'DENY', 'DENY'] and
            decision(inp) == 'ACCEPT',
            'active and inactive state observations and authorization gates')
    for index, row in enumerate(suite['cases']):
        ident = row['id']
        verdict = 'ACCEPT' if index == 0 else 'REJECT'
        expected = {'verdict': verdict,
                    'output': output if index == 0 else {}, 'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(row['input']['observations'] == inp['observations'] and
                decision(row['input']) == verdict and row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.did.metadata.verify',
                                      'input': row['input']},
                            'expected': expected},
                'RESOLVE-03 case contract: ' + ident)
    cached, alias, wrong_type = [row['input']['candidate']
                                 for row in suite['cases'][1:]]
    require(cached['resolutions'][2] == output['resolutions'][0] and
            cached['protected_operation_gate'][2] == 'DEFER' and
            alias['resolutions'][1]['didDocumentMetadata']['canonicalId'] ==
                inp['observations'][1]['record']['id'] and
            wrong_type['resolutions'][2]['didResolutionMetadata'] ==
                {'contentType': 'application/json'},
            'isolated cached state, alias, and content type defects')
    for name, mutate in (
        ('observed-at', lambda x: x['candidate']['resolutions'][0]['didDocumentMetadata']['sage'].update(observedAt=99)),
        ('observed-time', lambda x: x['candidate']['resolutions'][0]['didDocumentMetadata']['sage'].update(observedTime=101)),
        ('missing-state', lambda x: x['candidate']['resolutions'][1]['didDocumentMetadata']['sage'].pop('state')),
        ('false-deactivated', lambda x: x['candidate']['resolutions'][2]['didDocumentMetadata'].update(deactivated=False)),
        ('unauthenticated-source', lambda x: x['observations'][0].update(source_authenticated=False)),
        ('stale-observation', lambda x: x['observations'][0].update(observation_current=False)),
        ('long-source', lambda x: x['observations'][0].update(source='x' * 2049)),
        ('premature-authorization', lambda x: x['candidate']['protected_operation_gate'].__setitem__(0, 'ALLOW')),
    ):
        changed = copy.deepcopy(inp)
        mutate(changed)
        require(decision(changed) == 'REJECT', 'metadata control: ' + name)
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(all(any(binding['id'] == ident and binding['coverage'] == 'partial' and
                    binding['fixture_sha256'] == sha((root / 'vectors/0.10.0/current-spec' /
                                                     (ident + '.json')).read_bytes())
                    for binding in bindings['bindings']) for ident in IDS),
            'partial runtime bindings')
    return len(IDS), 8


if __name__ == '__main__':
    print(check())
