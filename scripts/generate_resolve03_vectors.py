"""Generate metadata and authorization-boundary fixtures for DID resolution."""

import copy
import hashlib
import json
from pathlib import Path

from generate_resolve01_vectors import project


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('RESOLVE-03-P', 'RESOLVE-03-N01', 'RESOLVE-03-N02', 'RESOLVE-03-N03')


def resolution(observation):
    record = observation['record']
    state = record['state']
    return {
        'didDocument': project(record),
        'didDocumentMetadata': {
            'deactivated': state == 'deactivated',
            'versionId': record['version'],
            'sage': {'state': state, 'controller': record['controller'],
                     'observedAt': observation['issued'],
                     'source': observation['source'],
                     'observedTime': observation['observed_time']}},
        'didResolutionMetadata': {'contentType': 'application/did+json'}}


def main():
    raw = (ROOT / 'vectors/0.10.0/reg08-scenarios.json').read_bytes()
    base = json.loads(raw)['cases'][0]['input']
    active = base['response']['body']['record']
    observations = []
    for state in ('active', 'created', 'deactivated'):
        record = copy.deepcopy(active)
        record['state'] = state
        observations.append({
            'record': record, 'issued': base['response']['body']['issued'],
            'observed_time': base['trusted_now'],
            'source': base['policy']['configured_origin'],
            'source_authenticated': True,
            'observation_current': True})
    good = {'observations': observations,
            'candidate': {'resolutions': [resolution(row) for row in observations],
                          'protected_operation_gate': ['DEFER', 'DENY', 'DENY']}}
    cached = copy.deepcopy(good)
    cached['candidate']['resolutions'][2] = copy.deepcopy(
        good['candidate']['resolutions'][0])
    cached['candidate']['protected_operation_gate'][2] = 'DEFER'
    alias = copy.deepcopy(good)
    alias['candidate']['resolutions'][1]['didDocumentMetadata']['canonicalId'] = active['id']
    wrong_type = copy.deepcopy(good)
    wrong_type['candidate']['resolutions'][2]['didResolutionMetadata']['contentType'] = 'application/json'
    rows = [
        ('RESOLVE-03-P', good, 'ACCEPT', 'active, created, and deactivated state from one current observation each'),
        ('RESOLVE-03-N01', cached, 'REJECT', 'cached active success reused after deactivation'),
        ('RESOLVE-03-N02', alias, 'REJECT', 'unapproved canonical identifier alias'),
        ('RESOLVE-03-N03', wrong_type, 'REJECT', 'incorrect DID document media type'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict,
                    'output': good['candidate'] if verdict == 'ACCEPT' else {},
                    'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'runtime',
                   'input': {'operation': 'sage.did.metadata.verify', 'input': inp},
                   'expected': expected}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c',
             'registry_source_sha256': hashlib.sha256(raw).hexdigest(),
             'scope': 'synthetic current observations; no live Registry authentication, proof verification, or protected dispatch',
             'cases': cases}
    (ROOT / 'vectors/0.10.0/resolve03-scenarios.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident in IDS:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
