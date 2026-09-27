"""Check HPKE-05 record prerequisite and provisional state scenarios."""

from current_spec_catalog import ROOT, load, require


IDS = ('HPKE-05-P', 'HPKE-05-N01', 'HPKE-05-N02',
       'HPKE-05-N03', 'HPKE-05-N04')
PLAINTEXT = '7075626c69632073657373696f6e207265636f7264'


def scenario(root, name):
    return load((root / 'vectors/0.10.0/session-scenarios' /
                 (name + '.json')).read_bytes())['steps']


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'HPKE-05 fixture identity')
    confirm = scenario(root, 'session-provisional-confirm')
    deadline = scenario(root, 'session-provisional-deadline')
    restart = scenario(root, 'session-restart')
    state = confirm[0]['input']
    first = confirm[3]['input']
    require(state['state'] == 'RESPONSE_SENT' and
            state['local_role'] == 'responder' and
            state['deadline_monotonic'] == 300 and
            first['seq'] == 7 and first['sender_role'] == 'initiator' and
            first['signature_verified'] is True and
            first['envelope_projection']['session_id'] == state['sid'] and
            confirm[3]['effects']['confirmations'] == 1 and
            confirm[4]['expected']['output']['state'] == 'ESTABLISHED',
            'HPKE-05 first valid initiator record and confirmation')
    positive = fixtures['HPKE-05-P']
    require(positive['input'] == {'operation': 'sage.session.record010.open',
            'input': {'seed_hex': state['seed_hex'],
                      'th_hex': state['th_hex'], 'direction': 'c2s',
                      'record_hex': first['record_hex'],
                      'caller_aad_hex': first['caller_aad_hex']}} and
            positive['expected'] == {'verdict': 'ACCEPT',
                'output': {'plaintext_hex': PLAINTEXT}, 'effects': {}},
            'HPKE-05 bounded record decryption prerequisite')

    deny = lambda effects: {'verdict': 'REJECT', 'output': {},
                             'effects': effects}
    require(confirm[1]['input'] == {'action': 'send'} and
            confirm[1]['expected']['verdict'] == 'REJECT' and
            confirm[1]['effects']['dispatch'] == 0 and
            confirm[2]['expected']['output']['state'] == 'RESPONSE_SENT' and
            fixtures['HPKE-05-N01']['input'] == {
                'operation': 'sage.hpke.provisional.verify',
                'input': {'state': state, 'action': confirm[1]['input'],
                          'trusted_monotonic': 0}} and
            fixtures['HPKE-05-N01']['expected'] == deny({
                'protected_dispatches': 0, 'confirmations': 0}),
            'HPKE-05 no responder send or dispatch before confirmation')

    expired = deadline[0]['input']
    require(expired['state'] == 'RESPONSE_SENT' and
            deadline[1]['input']['monotonic'] == expired['deadline_monotonic'] == 300 and
            deadline[2]['expected']['verdict'] == 'REJECT' and
            deadline[3]['expected']['output']['state'] == 'CLOSED' and
            deadline[2]['effects']['accepted'] == 0 and
            fixtures['HPKE-05-N02']['input'] == {
                'operation': 'sage.hpke.provisional.verify',
                'input': {'state': expired, 'action': deadline[2]['input'],
                          'trusted_monotonic': 300}} and
            fixtures['HPKE-05-N02']['expected'] == deny({
                'protected_dispatches': 0, 'confirmations': 0}),
            'HPKE-05 exact pending deadline closes without confirmation')

    hpke02 = load((root /
        'vectors/0.10.0/current-spec/HPKE-02-N01.json').read_bytes())
    initiation = hpke02['input']['input']['initiation_hex']
    nonce = load(bytes.fromhex(initiation))['nonce']
    require(nonce == state['tuple']['nonce'] and
            fixtures['HPKE-05-N03']['input'] == {
                'operation': 'sage.hpke.provisional.verify',
                'input': {'existing_state': 'ESTABLISHED',
                          'existing_sid': state['sid'],
                          'accepted_initiation_nonce': nonce,
                          'retransmitted_initiation_hex': initiation}} and
            fixtures['HPKE-05-N03']['expected'] == deny({
                'sessions_replaced': 0, 'protected_dispatches': 0}),
            'HPKE-05 retransmitted initiation cannot replace session')

    require(restart[0]['input']['state'] == 'ESTABLISHED' and
            restart[3]['input'] == {'action': 'restart'} and
            restart[4]['expected']['output']['state'] == 'CLOSED' and
            restart[5]['expected']['verdict'] == 'REJECT' and
            fixtures['HPKE-05-N04']['input'] == {
                'operation': 'sage.hpke.provisional.verify',
                'input': {'state': restart[0]['input'],
                          'restart_action': restart[3]['input'],
                          'resume_action': restart[5]['input']}} and
            fixtures['HPKE-05-N04']['expected'] == deny({
                'sessions_resumed': 0, 'protected_dispatches': 0}),
            'HPKE-05 restart discards old session state')
    return len(IDS)


if __name__ == '__main__':
    print('Verified HPKE-05 provisional-state fixtures:', check())
