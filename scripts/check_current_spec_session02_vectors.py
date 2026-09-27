"""Check SESSION-02 directional key, limit, and lifetime fixture provenance."""

import hmac

from current_spec_catalog import ROOT, load, require


IDS = ('SESSION-02-P', 'SESSION-02-N01', 'SESSION-02-N02',
       'SESSION-02-N03', 'SESSION-02-N04', 'CST-05-07')
SEQUENCES = (255, 256, 999)


def scenario(root, name):
    return load((root / 'vectors/0.10.0/session-scenarios' /
                 (name + '.json')).read_bytes())['steps']


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'SESSION-02 fixture identity')
    records = {row['id']: row for row in load((root /
        'vectors/0.10.0/session-records.json').read_bytes())['cases']}
    cases, opened = [], {}
    for direction in ('c2s', 's2c'):
        keys = []
        for seq in SEQUENCES:
            key = records[f'{direction}-key-{seq}']
            ident = f'{direction}-open-{seq}'
            row = records[ident]
            seed = bytes.fromhex(key['input']['seed_hex'])
            th = bytes.fromhex(key['input']['th_hex'])
            generation = seq // 256
            info = (f'sage-{direction}-key|0.10.0'.encode() + th +
                    generation.to_bytes(8, 'big'))
            derived = hmac.digest(seed, info + b'\x01', 'sha256')
            require(len(seed) == len(th) == 32 and
                    key['expected'] == {'verdict': 'ACCEPT',
                        'output': {'key_hex': derived.hex(),
                                   'generation': generation}} and
                    row['expected']['verdict'] == 'ACCEPT' and
                    int.from_bytes(bytes.fromhex(row['input']['record_hex'])[:8],
                                   'big') == seq,
                    'SESSION-02 independent directional key and record: ' + ident)
            keys.append(derived)
            cases.append({'id': ident, **{key: value for key, value in
                          row['input'].items() if key != 'sid'}})
            opened[ident] = row['expected']['output']['plaintext_hex']
        require(keys[0] != keys[1] != keys[2],
                'SESSION-02 generation boundary: ' + direction)
    require(fixtures['SESSION-02-P']['input'] == {
            'operation': 'sage.session.record.boundary.probe',
            'input': {'cases': cases}} and
            fixtures['SESSION-02-P']['expected'] == {'verdict': 'ACCEPT',
                'output': {'opened': opened}, 'effects': {}},
            'SESSION-02 six core record boundary probes')
    cap = records['seq-1000']
    require(cap['expected'] == {'verdict': 'REJECT', 'output': {}} and
            int.from_bytes(bytes.fromhex(cap['input']['record_hex'])[:8],
                           'big') == 1000 and
            fixtures['SESSION-02-N01']['input'] == {
                'operation': 'sage.session.record010.open',
                'input': {key: value for key, value in cap['input'].items()
                          if key != 'sid'}} and
            fixtures['SESSION-02-N01']['expected'] == {'verdict': 'REJECT',
                'output': {}, 'effects': {}},
            'SESSION-02 receiver rejects sequence 1000')

    deny = {'verdict': 'REJECT', 'output': {},
            'effects': {'accepted': 0, 'protected_dispatches': 0}}
    absolute = scenario(root, 'session-absolute-boundary')
    require(absolute[0]['input']['created_monotonic'] == 0 and
            absolute[20]['expected']['verdict'] == 'ACCEPT' and
            absolute[22]['input']['monotonic'] == 3600 and
            absolute[23]['expected']['verdict'] == 'REJECT' and
            absolute[24]['expected']['output']['state'] == 'CLOSED' and
            fixtures['SESSION-02-N02']['input'] == {
                'operation': 'sage.session.lifetime.verify',
                'input': {'state': absolute[0]['input'],
                          'trusted_monotonic': 3600,
                          'action': absolute[23]['input']}} and
            fixtures['SESSION-02-N02']['expected'] == deny,
            'SESSION-02 one-hour absolute boundary')
    idle = scenario(root, 'session-idle-boundary')
    require(idle[2]['expected']['verdict'] == 'ACCEPT' and
            idle[3]['expected']['output']['last_activity'] == 599 and
            idle[4]['input']['monotonic'] == 1199 and
            idle[5]['expected']['verdict'] == 'REJECT' and
            idle[6]['expected']['output']['state'] == 'CLOSED' and
            fixtures['SESSION-02-N03']['input'] == {
                'operation': 'sage.session.lifetime.verify',
                'input': {'state': idle[0]['input'],
                          'last_accepted_monotonic': 599,
                          'trusted_monotonic': 1199,
                          'action': idle[5]['input']}} and
            fixtures['SESSION-02-N03']['expected'] == deny,
            'SESSION-02 ten-minute idle boundary')

    altered = load((root / 'vectors/0.10.0/current-spec/SESSION-02-N04.json')
                   .read_bytes())['input']['input']['state']
    original = absolute[0]['input']
    require(original['policy']['rekey_interval'] == 256 and
            altered == dict(original, policy=dict(original['policy'],
                                                  rekey_interval=512)) and
            fixtures['SESSION-02-N04']['input'] == {
                'operation': 'sage.session.policy.verify',
                'input': {'state': altered}} and
            fixtures['SESSION-02-N04']['expected'] == {'verdict': 'REJECT',
                'output': {}, 'effects': {'sessions_created': 0,
                                          'protected_dispatches': 0}},
            'SESSION-02 fixed rekey interval')
    provisional = scenario(root, 'session-provisional-no-clock-reset')
    require(provisional[0]['input']['state'] == 'RESPONSE_SENT' and
            provisional[0]['input']['created_monotonic'] == 0 and
            provisional[2]['expected']['verdict'] == 'ACCEPT' and
            provisional[3]['expected']['output']['state'] == 'ESTABLISHED' and
            provisional[3]['expected']['output']['last_activity'] == 299 and
            provisional[25]['input']['monotonic'] == 3600 and
            provisional[26]['expected']['verdict'] == 'REJECT' and
            provisional[27]['expected']['output']['state'] == 'CLOSED' and
            fixtures['CST-05-07']['input'] == {
                'operation': 'sage.session.provisional.lifetime.verify',
                'input': {'state': provisional[0]['input'],
                          'confirm_at_monotonic': 299,
                          'confirmation': provisional[2]['input'],
                          'final_monotonic': 3600,
                          'final_action': provisional[26]['input']}} and
            fixtures['CST-05-07']['expected'] == deny,
            'SESSION-02 confirmation does not restart absolute lifetime')
    return len(IDS)


if __name__ == '__main__':
    print('Verified SESSION-02 key and lifetime fixtures:', check())
