"""Check SESSION-03 record, nonce, and complete-AAD fixture provenance."""

from current_spec_catalog import ROOT, load, require


IDS = ('SESSION-03-P', 'SESSION-03-N01', 'SESSION-03-N02',
       'SESSION-03-N03', 'SESSION-03-N04', 'SESSION-03-N05',
       'CST-03-01', 'CST-03-02')


def check(root=ROOT):
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    require(all(row['id'] == ident and row['track'] == 'runtime' for
                ident, row in fixtures.items()), 'SESSION-03 fixture identity')
    records = {row['id']: row for row in load((root /
        'vectors/0.10.0/session-records.json').read_bytes())['cases']}

    def control(name):
        return {key: value for key, value in records[name]['input'].items()
                if key != 'sid'}

    def direct(ident, name):
        source = records[name]
        require(fixtures[ident]['input'] == {
                'operation': source['operation'].replace('.record.', '.record010.'),
                'input': control(name)} and
                fixtures[ident]['expected'] == {
                'verdict': source['expected']['verdict'],
                'output': source['expected']['output'], 'effects': {}},
                'SESSION-03 direct record source: ' + ident)

    for ident, name in (('SESSION-03-P', 'c2s-open-0'),
                        ('SESSION-03-N01', 'nonce-valid-tag'),
                        ('SESSION-03-N03', 'aad-changed'),
                        ('SESSION-03-N04', 'aad-open-4034')):
        direct(ident, name)
    valid = control('c2s-open-0')
    wire = bytes.fromhex(valid['record_hex'])
    nonce = control('nonce-valid-tag')
    require(len(wire) >= 36 and wire[:20] == b'\x00' * 20 and
            valid['direction'] == 'c2s' and
            len(bytes.fromhex(valid['caller_aad_hex'])) == 2 and
            nonce['record_hex'] != valid['record_hex'] and
            bytes.fromhex(nonce['record_hex'])[:8] == wire[:8] and
            bytes.fromhex(nonce['record_hex'])[8:20] != wire[8:20] and
            records['nonce-valid-tag']['expected']['verdict'] == 'REJECT',
            'SESSION-03 known answer and nonconforming nonce')

    wrong = dict(valid, direction='s2c')
    require(fixtures['SESSION-03-N02']['input'] == {
            'operation': 'sage.session.record010.open', 'input': wrong} and
            fixtures['SESSION-03-N02']['expected'] == {
                'verdict': 'REJECT', 'output': {}, 'effects': {}},
            'SESSION-03 wrong direction changes only direction')
    changed = control('aad-changed')
    require(changed['record_hex'] == valid['record_hex'] and
            changed['caller_aad_hex'] != valid['caller_aad_hex'] and
            records['aad-changed']['expected']['verdict'] == 'REJECT',
            'SESSION-03 changed AAD rejects unchanged record')

    short = control('short')
    oversized = control('plaintext-size-8388573')
    require(len(bytes.fromhex(short['record_hex'])) == 35 and
            oversized['plaintext']['length'] == 8 * 1024 * 1024 - 35 and
            records['short']['expected']['verdict'] == 'REJECT' and
            records['plaintext-size-8388573']['expected']['verdict'] == 'REJECT'
            and fixtures['SESSION-03-N05']['input'] == {
                'operation': 'sage.session.record.bounds.pair',
                'input': {'short': short, 'oversized': oversized}} and
            fixtures['SESSION-03-N05']['expected'] == {'verdict': 'ACCEPT',
                'output': {'short_verdict': 'REJECT',
                           'oversized_verdict': 'REJECT'}, 'effects': {}},
            'SESSION-03 short and oversized record bounds')

    for ident, suffix, length, verdict in (
            ('CST-03-01', '4033', 4033, 'ACCEPT'),
            ('CST-03-02', '4034', 4034, 'REJECT')):
        opened = records['aad-open-' + suffix]
        sealed = records['aad-seal-' + suffix]
        require(len(bytes.fromhex(opened['input']['caller_aad_hex'])) ==
                len(bytes.fromhex(sealed['input']['caller_aad_hex'])) == length
                and 63 + length == (4096 if length == 4033 else 4097) and
                opened['expected']['verdict'] == sealed['expected']['verdict'] ==
                verdict and
                fixtures[ident]['input'] == {
                    'operation': 'sage.session.record.aad.pair',
                    'input': {'open': control('aad-open-' + suffix),
                              'seal': control('aad-seal-' + suffix)}} and
                fixtures[ident]['expected'] == {'verdict': 'ACCEPT',
                    'output': {'open_verdict': verdict,
                               'open_output': opened['expected']['output'],
                               'seal_verdict': verdict,
                               'seal_output': sealed['expected']['output']},
                    'effects': {}},
                'SESSION-03 complete AAD boundary: ' + ident)
    require(fixtures['SESSION-03-N04']['input']['input'] ==
            fixtures['CST-03-02']['input']['input']['open'],
            'SESSION-03 receiver AAD overflow is the same boundary')
    return len(IDS)


if __name__ == '__main__':
    print('Verified SESSION-03 record and AAD fixtures:', check())
