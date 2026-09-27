"""Check the independently authored JCS byte relation fixtures."""

import unicodedata

from current_spec_catalog import ROOT, load, require


IDS = ('JCS-03-P', 'JCS-03-N01', 'JCS-03-N02', 'JCS-03-N03')


def check(root=ROOT):
    pairs = {}
    for ident in IDS:
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture['id'] == ident and fixture['track'] == 'runtime' and
                fixture['input']['operation'] == 'jcs.order_pair' and
                fixture['expected']['verdict'] == 'ACCEPT',
                'JCS byte relation fixture identity')
        pair = fixture['input']['input']
        outputs = fixture['expected']['output']
        raw = [bytes.fromhex(pair[side]['document_hex']) for side in ('left', 'right')]
        expected = [bytes.fromhex(outputs[side + '_output']['canonical_hex'])
                    for side in ('left', 'right')]
        require(all(outputs[side + '_verdict'] == 'ACCEPT'
                    for side in ('left', 'right')) and
                all(item.decode('utf-8').encode('utf-8') == item
                    for item in raw + expected),
                'JCS byte relation encoding')
        pairs[ident] = raw, expected
    require(pairs['JCS-03-P'][0][0] != pairs['JCS-03-P'][0][1] and
            pairs['JCS-03-P'][1][0] == pairs['JCS-03-P'][1][1],
            'member-order invariance')
    require(pairs['JCS-03-N01'][1][0] != pairs['JCS-03-N01'][1][1],
            'array-order preservation')
    first, second = (item.decode() for item in pairs['JCS-03-N02'][1])
    require(first != second and unicodedata.normalize('NFC', first) ==
            unicodedata.normalize('NFC', second), 'Unicode non-normalization')
    require(pairs['JCS-03-N03'][0][0] != pairs['JCS-03-N03'][0][1] and
            pairs['JCS-03-N03'][1][0] == pairs['JCS-03-N03'][1][1] and
            b'1.0' in pairs['JCS-03-N03'][0][0] and
            b'1.0' not in pairs['JCS-03-N03'][1][0],
            'ECMAScript number rendering')
    return len(IDS)


if __name__ == '__main__':
    print('Verified JCS byte relation fixtures:', check())
