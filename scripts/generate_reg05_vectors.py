"""Bind fresh authoritative Registry observations to public gate scenarios."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'vectors/0.10.0/registry010.json'
OUTPUT = ROOT / 'vectors/0.10.0/reg05-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CASES = (
    ('REG-05-P', 'registry-freshness', 0,
     'one finalized snapshot accepted at the exact five-second gate'),
    ('REG-05-N01', 'registry-reject-keys_block_hash', 0,
     'record and keys from different finalized blocks'),
    ('REG-05-N02', 'registry-unfinalized-reorg', 0,
     'unfinalized state cannot authorize or become a permanent tombstone'),
    ('REG-05-N03', 'registry-reject-ready', 0,
     'claimed head without established authority readiness'),
    ('REG-05-N04', 'revoked-signing', 1,
     'freshly observed revoked signing key denies an earlier selection'),
    ('REG-05-N05', 'registry-freshness', 2,
     'same snapshot rejected after the five-second gate'),
)
CONTROLS = (
    ('untrusted-source', 'registry-reject-source', 0),
    ('untrusted-clock', 'registry-reject-clock_trusted', 0),
    ('refreshed-after-delay', 'storage-delay-and-refresh', 2),
)


def main():
    raw = SOURCE.read_bytes()
    scenarios = {case['id']: case for case in json.loads(raw)['cases']}

    def select(ident, scenario_id, focus, purpose=None):
        scenario = scenarios[scenario_id]
        expected = scenario['steps'][focus]['expected']
        row = {'id': ident, 'source_scenario': scenario_id,
               'focus_step': focus, 'scenario': scenario,
               'expected': {**expected, 'effects': {}}}
        if purpose is not None:
            row['purpose'] = purpose
        return row

    suite = {
        'schema_version': 1, 'spec_revision': SPEC,
        'source_sha256': hashlib.sha256(raw).hexdigest(),
        'scope': 'synthetic trusted source and clock with local journals; no network or deployed finality',
        'cases': [select(*case) for case in CASES],
        'supplemental': [select(*control) for control in CONTROLS],
    }
    OUTPUT.write_text(json.dumps(suite, indent=2) + '\n')
    for row in suite['cases']:
        ident = row['id']
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'runtime',
                   'input': {'operation': 'sage.registry.observation.sequence',
                             'input': {'scenario': row['scenario'],
                                       'focus_step': row['focus_step']}},
                   'expected': row['expected']}
        (ROOT / 'vectors/0.10.0/current-spec' / (ident + '.json')).write_text(
            json.dumps(fixture, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    ids = tuple(row['id'] for row in suite['cases'])
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in ids]
    for ident in ids:
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        bindings['bindings'].append({
            'id': ident, 'track': 'runtime', 'fixture': relative,
            'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')
    print('Generated', len(suite['cases']), 'REG-05 cases and',
          len(suite['supplemental']), 'controls')


if __name__ == '__main__':
    main()
