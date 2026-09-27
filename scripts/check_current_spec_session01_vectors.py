"""Check SESSION-01 session identity and pinned-tuple fixture provenance."""

import base64
import hashlib

from current_spec_catalog import ROOT, load, require


IDS = ('SESSION-01-P', 'SESSION-01-N01', 'SESSION-01-N02',
       'SESSION-01-N03', 'CST-04-01', 'CST-04-02',
       'CST-04-03', 'CST-04-04')


def scenario(root, name):
    return load((root / 'vectors/0.10.0/session-scenarios' /
                 (name + '.json')).read_bytes())['steps']


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'SESSION-01 fixture identity')
    state = scenario(root, 'session-pinned-did')[0]['input']
    schedule = {row['id']: row for row in load((root /
        'vectors/0.10.0/hpke-schedule.json').read_bytes())['cases']}
    completed = schedule['schedule-0']['expected']['output']
    th = hashlib.sha256(bytes.fromhex(completed['transcript_hex'])).digest()
    sid = base64.urlsafe_b64encode(hashlib.sha256(
        b'sage-session|0.10.0' + th).digest()[:16]).decode().rstrip('=')
    require(len(bytes.fromhex(state['seed_hex'])) == len(th) == 32 and
            completed['seed_hex'] == state['seed_hex'] and
            completed['th_hex'] == state['th_hex'] == th.hex() and
            completed['sid'] == state['sid'] == sid and len(sid) == 22 and
            sid != state['tuple']['kid'] and
            state['local_role'] == 'responder',
            'SESSION-01 transcript-bound public session ID')
    require(fixtures['SESSION-01-P']['input'] == {
            'operation': 'sage.session.sid.project',
            'input': {'seed_hex': state['seed_hex'], 'th_hex': th.hex()}} and
            fixtures['SESSION-01-P']['expected'] == {'verdict': 'ACCEPT',
                'output': {'c2s_sid': sid, 's2c_sid': sid}, 'effects': {}},
            'SESSION-01 dual-direction core ID projection')

    def deny(ident, inp, effect='accepted'):
        require(fixtures[ident]['input'] == inp and
                fixtures[ident]['expected'] == {'verdict': 'REJECT',
                    'output': {}, 'effects': {effect: 0,
                                              'protected_dispatches': 0}},
                'SESSION-01 denied boundary: ' + ident)

    deny('SESSION-01-N01', {'operation': 'sage.session.create.verify',
        'input': {'external_secret_hex': state['seed_hex'],
                  'th_hex': th.hex(), 'local_role': state['local_role']}},
        'sessions_created')
    other_th = schedule['schedule-1']['expected']['output']['th_hex']
    require(other_th != th.hex() and len(bytes.fromhex(other_th)) == 32,
            'SESSION-01 independent other transcript')
    deny('SESSION-01-N02', {'operation': 'sage.session.bound.verify',
        'input': {'state': state, 'candidate_th_hex': other_th}})

    names = {'SESSION-01-N03': 'session-pinned-sender-role',
             'CST-04-01': 'session-pinned-did',
             'CST-04-02': 'session-pinned-kid-active-alternative'}
    for ident, name in names.items():
        steps = scenario(root, name)
        require(steps[0]['input']['sid'] == sid and
                steps[1]['expected']['verdict'] == 'REJECT' and
                steps[1]['effects']['accepted'] == 0 and
                steps[1]['effects']['dispatch'] == 0 and
                steps[3]['expected']['verdict'] == 'ACCEPT',
                'SESSION-01 negative/control scenario: ' + name)
        deny(ident, {'operation': 'sage.session.bound.verify',
            'input': {'state': steps[0]['input'],
                      'action': steps[1]['input']}})
    require(scenario(root, 'session-pinned-sender-role')[1]['input']
            ['sender_role'] == state['local_role'],
            'SESSION-01 same-local-role record')
    require(scenario(root, 'session-pinned-did')[1]['input']
            ['signature_verified'] is True,
            'SESSION-01 valid signature cannot replace DID equality')

    mismatches = ('session-pinned-recipient', 'session-pinned-sender-role',
                  'session-pinned-context_id', 'session-pinned-session_id')
    candidates = []
    for name in mismatches:
        steps = scenario(root, name)
        require(steps[0]['input']['sid'] == sid and
                steps[1]['expected']['verdict'] == 'REJECT' and
                steps[1]['effects']['accepted'] == 0 and
                steps[1]['effects']['dispatch'] == 0 and
                steps[3]['expected']['verdict'] == 'ACCEPT',
                'SESSION-01 isolated mismatch: ' + name)
        candidates.append(steps[1]['input'])
    deny('CST-04-03', {'operation': 'sage.session.bound.verify',
        'input': {'state': state, 'candidates': candidates}})

    checks = []
    for name, verdict in (('session-registry-revoked-init-key', 'REJECT'),
                          ('session-registry-unrelated', 'ACCEPT')):
        steps = scenario(root, name)
        require(steps[0]['input']['sid'] == sid and
                steps[1]['input']['action'] == 'registry' and
                steps[3]['expected']['verdict'] == verdict and
                steps[3]['effects']['dispatch'] == (verdict == 'ACCEPT') and
                steps[1]['effects']['closed'] == (verdict == 'REJECT'),
                'SESSION-01 selected versus unrelated registry change')
        checks.append({'registry': steps[1]['input'],
                       'receive': steps[3]['input']})
    require(fixtures['CST-04-04']['input'] == {
        'operation': 'sage.session.registry.bound.verify',
        'input': {'state': state, 'checks': checks}} and
        fixtures['CST-04-04']['expected'] == {'verdict': 'ACCEPT',
            'output': {'revoked': 'REJECT', 'unrelated': 'ACCEPT'},
            'effects': {}}, 'SESSION-01 registry change pair')
    return len(IDS)


if __name__ == '__main__':
    print('Verified SESSION-01 identity and tuple fixtures:', check())
