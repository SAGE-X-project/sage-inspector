"""Check SESSION-04 send-allocation fixtures against independent scenarios."""

from current_spec_catalog import ROOT, load, require, sha


IDS = ('SESSION-04-P', 'SESSION-04-N01', 'SESSION-04-N02', 'SESSION-04-N03')
BASE = 'vectors/0.10.0/session-scenarios/'


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'SESSION-04 fixture identity')
    concurrent_raw = (root / BASE / 'session-concurrent-send.json').read_bytes()
    gap_raw = (root / BASE / 'session-transport-gap.json').read_bytes()
    concurrent = load(concurrent_raw)['steps']
    gap = load(gap_raw)['steps']
    require(concurrent[1]['operation'] == 'subject.parallel' and
            concurrent[1]['input'] == {'action': 'parallel-send', 'count': 16,
                                        'barrier': 'before-atomic-commit'} and
            concurrent[1]['expected']['output']['sequences'] == list(range(16)) and
            concurrent[2]['expected']['output']['next_send'] == 16 and
            concurrent[3]['expected']['output']['sequences'] == [16] and
            concurrent[4]['expected']['output']['next_send'] == 17,
            'independent concurrent allocation scenario')
    require(gap[1]['input'] == {'action': 'send', 'transport_failure': True} and
            gap[1]['expected']['output']['sequences'] == [0] and
            gap[2]['expected']['output']['next_send'] == 1 and
            gap[3]['expected']['output']['sequences'] == [1] and
            gap[5]['expected']['output'] == {'identical_ciphertext': True} and
            gap[7]['input'] == {'action': 'retransmit', 'seq': 0,
                                'changed_plaintext': True} and
            gap[7]['expected']['verdict'] == 'REJECT',
            'independent transport gap and retransmission scenario')
    source = (root / 'verification/0.10.0/snapshot/spec/05-session.md').read_text()
    require('The legacy separate MAC path\nis not part of 0.10.0' in source and
            'Key/nonce reuse to\nencode a different plaintext is forbidden' in source,
            'pinned SESSION-04 MAC and nonce rule')
    inputs = {
        'SESSION-04-P': {'operation': 'sage.session.concurrent.send', 'input': {
            'scenario_id': 'session-concurrent-send', 'scenario_sha256': sha(concurrent_raw),
            'parallel_count': 16, 'barrier': 'before-atomic-commit'}},
        'SESSION-04-N01': {'operation': 'sage.session.sequence.reuse', 'input': {
            'scenario_id': 'session-transport-gap', 'scenario_sha256': sha(gap_raw),
            'allocated_sequence': 0, 'transport_failed': True, 'proposed_sequence': 0}},
        'SESSION-04-N02': {'operation': 'sage.session.legacy_mac.verify', 'input': {
            'mechanism': 'separate-mac', 'authenticated_bytes': 'caller-selected-unrelated'}},
        'SESSION-04-N03': {'operation': 'sage.session.retransmission.replace', 'input': {
            'scenario_id': 'session-transport-gap', 'scenario_sha256': sha(gap_raw),
            'sequence': 0, 'changed_plaintext': True}},
    }
    expected = {
        'SESSION-04-P': {'verdict': 'ACCEPT', 'output': {
            'sequences': list(range(16)), 'next_sequence': 16},
            'effects': {'allocated': 16, 'emitted': 16}},
        'SESSION-04-N01': {'verdict': 'REJECT', 'output': {}, 'effects': {}},
        'SESSION-04-N02': {'verdict': 'REJECT', 'output': {}, 'effects': {}},
        'SESSION-04-N03': {'verdict': 'REJECT', 'output': {}, 'effects': {}},
    }
    for ident in IDS:
        require(fixtures[ident]['input'] == inputs[ident] and
                fixtures[ident]['expected'] == expected[ident],
                'SESSION-04 independent fixture relation: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print('Verified SESSION-04 send-allocation fixtures:', check())
