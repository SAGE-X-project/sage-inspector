"""Check SESSION-05 replay fixtures against independent scenario expectations."""

from current_spec_catalog import ROOT, load, require, sha


IDS = ('SESSION-05-P', 'SESSION-05-N01', 'SESSION-05-N02',
       'SESSION-05-N03', 'SESSION-05-N04')
BASE = 'vectors/0.10.0/session-scenarios/'


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'SESSION-05 fixture identity')
    names = ('session-reorder-replay', 'session-concurrent-duplicate',
             'session-invalid-does-not-reserve')
    raw = {name: (root / BASE / (name + '.json')).read_bytes() for name in names}
    steps = {name: load(value)['steps'] for name, value in raw.items()}
    reorder = steps['session-reorder-replay']
    concurrent = steps['session-concurrent-duplicate']
    invalid = steps['session-invalid-does-not-reserve']
    require([reorder[i]['input'].get('seq') for i in (1, 3, 5, 7, 9)] ==
            [999, 0, 256, 0, 1000] and
            [reorder[i]['expected']['verdict'] for i in (1, 3, 5, 7, 9)] ==
            ['ACCEPT', 'ACCEPT', 'ACCEPT', 'REJECT', 'REJECT'],
            'independent reorder, duplicate, and cap scenario')
    require(concurrent[1]['operation'] == 'subject.parallel' and
            concurrent[1]['input']['copies'] == 16 and
            concurrent[1]['input']['barrier'] == 'before-atomic-commit' and
            concurrent[1]['expected']['output']['accepted'] == 1 and
            concurrent[1]['expected']['output']['rejected'] == 15 and
            concurrent[3]['expected']['verdict'] == 'REJECT',
            'independent concurrent duplicate scenario')
    require(invalid[1]['input']['invalid'] == 'tag' and
            invalid[1]['input']['seq'] == 999 and
            invalid[1]['expected']['verdict'] == 'REJECT' and
            invalid[2]['expected']['output']['received'] == [] and
            invalid[3]['input']['seq'] == 999 and
            invalid[3]['expected']['verdict'] == 'ACCEPT',
            'independent failed AEAD reservation scenario')
    source = (root / 'verification/0.10.0/snapshot/spec/05-session.md').read_text()
    require('1024-slot\nsliding bitmap' in source and
            'fixed\nmessage cap still applies' in source and
            'at most one acceptance' in source,
            'pinned replay window and cap rule')
    identifiers = {
        'SESSION-05-P': ('sage.session.reorder.verify', names[0]),
        'SESSION-05-N01': ('sage.session.concurrent.duplicate.verify', names[1]),
        'SESSION-05-N02': ('sage.session.invalid.tag.no_advance.verify', names[2]),
        'SESSION-05-N03': ('sage.session.duplicate.verify', names[0]),
    }
    for ident, (operation, name) in identifiers.items():
        require(fixtures[ident]['input'] == {'operation': operation, 'input': {
            'scenario_id': name, 'scenario_sha256': sha(raw[name])}},
            'SESSION-05 scenario identity: ' + ident)
    require(fixtures['SESSION-05-N04']['input'] == {
        'operation': 'sage.session.out_of_window.verify', 'input': {
            'window_slots': 1024, 'max_records_per_direction': 1000,
            'highest_sequence': 1024, 'candidate_sequence': 0}},
            'SESSION-05 unreachable window input')
    require(all(fixtures[ident]['expected'] == {'verdict': 'ACCEPT',
            'output': output, 'effects': {}} for ident, output in (
                ('SESSION-05-P', {'accepted_sequences': [999, 0, 256]}),
                ('SESSION-05-N01', {'accepted': 1, 'rejected': 15}),
                ('SESSION-05-N02', {'bad_tag': 'REJECT', 'valid_same_sequence': 'ACCEPT'})))
            and all(fixtures[ident]['expected'] == {'verdict': 'REJECT',
                'output': {}, 'effects': {}} for ident in
                ('SESSION-05-N03', 'SESSION-05-N04')),
            'SESSION-05 expected outcome relation')
    return len(IDS)


if __name__ == '__main__':
    print('Verified SESSION-05 replay fixtures:', check())
