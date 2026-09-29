"""Audit Registry freshness scenarios against independent source boundaries."""

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/reg05-scenarios.json'
ORIGINAL = 'vectors/0.10.0/registry010.json'
IDS = ('REG-05-P', 'REG-05-N01', 'REG-05-N02', 'REG-05-N03',
       'REG-05-N04', 'REG-05-N05')
CONTROLS = ('untrusted-source', 'untrusted-clock', 'refreshed-after-delay')
SPEC = '5bcf511e604579afa63f434013447f44b6858828'


def check(root=ROOT):
    original_raw = (root / ORIGINAL).read_bytes()
    scenarios = {row['id']: row for row in load(original_raw)['cases']}
    suite = load((root / SOURCE).read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC
            and suite['source_sha256'] == sha(original_raw)
            and tuple(row['id'] for row in suite['cases']) == IDS
            and tuple(row['id'] for row in suite['supplemental']) == CONTROLS,
            'REG-05 current source and case inventory')
    rows = {row['id']: row for row in suite['cases']}
    extras = {row['id']: row for row in suite['supplemental']}
    mapping = {
        'REG-05-P': ('registry-freshness', 0),
        'REG-05-N01': ('registry-reject-keys_block_hash', 0),
        'REG-05-N02': ('registry-unfinalized-reorg', 0),
        'REG-05-N03': ('registry-reject-ready', 0),
        'REG-05-N04': ('revoked-signing', 1),
        'REG-05-N05': ('registry-freshness', 2),
        'untrusted-source': ('registry-reject-source', 0),
        'untrusted-clock': ('registry-reject-clock_trusted', 0),
        'refreshed-after-delay': ('storage-delay-and-refresh', 2),
    }
    for ident, row in {**rows, **extras}.items():
        scenario_id, focus = mapping[ident]
        scenario = scenarios[scenario_id]
        require(row['source_scenario'] == scenario_id and
                row['focus_step'] == focus and row['scenario'] == scenario and
                row['expected'] == {
                    **scenario['steps'][focus]['expected'], 'effects': {}},
                'independently authored source scenario: ' + ident)
    positive = rows['REG-05-P']['scenario']['steps'][0]['request']
    stale = rows['REG-05-N05']['scenario']['steps'][2]['request']
    require(rows['REG-05-P']['scenario'] == rows['REG-05-N05']['scenario']
            and positive['action'] == stale['action'] == 'select'
            and positive['snapshot'] == stale['snapshot']
            and positive['snapshot']['acquired_ms'] == 10000
            and positive['times'][0]['mono_ms'] ==
                stale['times'][0]['mono_ms'] == 10000
            and positive['times'][-1]['mono_ms'] == 15000
            and stale['times'][-1]['mono_ms'] == 16000
            and rows['REG-05-P']['expected']['verdict'] == 'ACCEPT'
            and rows['REG-05-N05']['expected']['verdict'] == 'REJECT',
            'exact five-second acceptance and six-second denial')
    mixed = rows['REG-05-N01']['scenario']['steps'][0]['request']
    require(mixed['snapshot']['block_hash'] !=
                mixed['snapshot']['keys_block_hash']
            and mixed['snapshot']['finalized'] and mixed['snapshot']['ready']
            and mixed['clock_ok'] and mixed['source_ok']
            and rows['REG-05-N01']['expected']['verdict'] == 'REJECT',
            'mixed finalized record and keys block hashes')
    unfinalized = rows['REG-05-N02']['scenario']['steps']
    require(not unfinalized[0]['request']['snapshot']['finalized']
            and unfinalized[0]['expected']['verdict'] == 'REJECT'
            and unfinalized[1]['expected']['output']['tombstone'] is False
            and unfinalized[2]['request']['snapshot']['finalized']
            and unfinalized[2]['expected']['verdict'] == 'ACCEPT',
            'unfinalized revocation cannot become permanent tombstone')
    withheld = rows['REG-05-N03']['scenario']['steps'][0]['request']
    require(not withheld['snapshot']['ready']
            and withheld['snapshot']['finalized']
            and withheld['source_ok'] and withheld['clock_ok']
            and rows['REG-05-N03']['expected']['verdict'] == 'REJECT',
            'readiness not established despite claimed finalized head')
    revoked = rows['REG-05-N04']['scenario']['steps']
    require(revoked[0]['request']['action'] == 'select'
            and revoked[0]['expected']['verdict'] == 'ACCEPT'
            and revoked[1]['request']['action'] == 'check'
            and revoked[1]['request']['snapshot']['version'] == '3'
            and next(key for key in revoked[1]['request']['snapshot']['keys']
                     if key['name'] == 'signing-1')['state'] == 'revoked'
            and revoked[1]['expected']['verdict'] == 'REJECT',
            'earlier selection cannot authorize after observed revocation')
    untrusted = extras['untrusted-source']['scenario']['steps'][0]['request']
    clock = extras['untrusted-clock']['scenario']['steps'][0]['request']
    refreshed = extras['refreshed-after-delay']['scenario']['steps']
    require(untrusted['source_ok']
            and untrusted['snapshot']['source'] == 'peer-resolver'
            and not clock['clock_ok']
            and refreshed[0]['expected']['verdict'] == 'REJECT'
            and refreshed[2]['expected']['verdict'] == 'ACCEPT'
            and refreshed[2]['request']['snapshot']['acquired_ms'] == 16000,
            'untrusted source/clock and new observation after delay')
    for ident in IDS:
        row = rows[ident]
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation':
                                      'sage.registry.observation.sequence',
                                      'input': {'scenario': row['scenario'],
                                                'focus_step': row['focus_step']}},
                            'expected': row['expected']},
                'REG-05 runtime fixture contract: ' + ident)
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(manifest['spec_revision'] == SPEC and
            manifest['source_sha256']['spec/09-registry.md'] ==
                '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02',
            'pinned current observation chapter')
    return len(IDS), len(CONTROLS)


if __name__ == '__main__':
    print('Verified REG-05 cases and controls:', check())
