"""Check CARD-01 closed-card fixtures and isolated total-byte boundary."""

from current_spec_catalog import ROOT, load, require
from check_current_spec_jcs_exclusion_vectors import verify_card


SOURCE_IDS = {
    'CARD-01-P': 'card-valid',
    'CARD-01-N01': 'card-unknown',
    'CARD-01-N02': 'card-services',
    'CARD-01-N03': 'card-wrong-key',
    'CARD-01-N05': 'card-version',
}
IDS = ('CARD-01-P', 'CARD-01-N01', 'CARD-01-N02',
       'CARD-01-N03', 'CARD-01-N04', 'CARD-01-N05')


def check(root=ROOT):
    source = load((root / 'vectors/0.10.0/registry-records.json').read_bytes())
    records = {row['id']: row for row in source['cases']
               if row['operation'] == 'sage.card.verify'}
    fixtures = {ident: load((root / 'vectors/0.10.0/current-spec' /
                    (ident + '.json')).read_bytes()) for ident in IDS}
    for ident in IDS:
        require(fixtures[ident]['id'] == ident and
                fixtures[ident]['track'] == 'runtime',
                'CARD-01 fixture identity: ' + ident)
    for ident, source_id in SOURCE_IDS.items():
        record = records[source_id]
        require(fixtures[ident]['input'] == {
                    'operation': record['operation'], 'input': record['input']} and
                fixtures[ident]['expected'] == dict(record['expected'], effects={}),
                'CARD-01 independent record: ' + ident)
    control = records['card-valid']['input']
    raw = bytes.fromhex(control['card_hex'])
    card = load(raw)
    require(len(raw) < 65536 and card['version'] == '0.10.0' and
            card['id'] == control['record']['id'] == control['expected_peer'] and
            card['services'] == control['record']['services'] and
            card['recordVersion'] == control['record']['version'],
            'CARD-01 valid registry-bound card')
    verify_card(card, control['record'])
    oversized = fixtures['CARD-01-N04']
    candidate = oversized['input']['input']
    require(oversized['input']['operation'] == 'sage.card.verify' and
            all(candidate[field] == control[field] for field in control
                if field != 'card_hex') and
            bytes.fromhex(candidate['card_hex']) ==
                raw + b' ' * (65537 - len(raw)) and
            len(bytes.fromhex(candidate['card_hex'])) == 65537 and
            load(bytes.fromhex(candidate['card_hex'])) == card and
            oversized['expected'] == {
                'verdict': 'REJECT', 'output': {}, 'effects': {}},
            'CARD-01 isolated encoded-card size limit')
    mutated = {ident: load(bytes.fromhex(fixtures[ident]['input']['input']
                       ['card_hex'])) for ident in SOURCE_IDS if ident != 'CARD-01-P'}
    for ident in mutated:
        candidate = fixtures[ident]['input']['input']
        require(all(candidate[field] == control[field] for field in control
                    if field != 'card_hex'),
                'CARD-01 trusted context drift: ' + ident)
    def unsigned(value):
        result = {key: item for key, item in value.items() if key != 'proof'}
        result['proof'] = {key: item for key, item in value['proof'].items()
                           if key != 'proofValue'}
        return result
    canonical = unsigned(card)
    unknown = unsigned(mutated['CARD-01-N01'])
    services = unsigned(mutated['CARD-01-N02'])
    wrong_key = unsigned(mutated['CARD-01-N03'])
    version = unsigned(mutated['CARD-01-N05'])
    require(unknown.pop('keys', None) == [] and unknown == canonical and
            services.pop('services') != canonical['services'] and
            services == {key: item for key, item in canonical.items()
                         if key != 'services'} and
            wrong_key['proof'].pop('verificationMethod') !=
                canonical['proof']['verificationMethod'] and
            wrong_key == {**canonical, 'proof': {
                key: item for key, item in canonical['proof'].items()
                if key != 'verificationMethod'}} and
            version.pop('version') != canonical['version'] and
            version == {key: item for key, item in canonical.items()
                        if key != 'version'},
            'CARD-01 schema, service, key, and version boundaries')
    spec = (root / 'verification/0.10.0/snapshot/spec/07-a2a.md').read_text()
    require('at most 65536 bytes' in spec and
            'unknown members, duplicate members and null values MUST be rejected' in spec and
            'exact registry `services` array' in spec and
            'exact string `0.10.0`' in spec,
            'pinned CARD-01 closed schema')
    return len(IDS)


if __name__ == '__main__':
    print('Verified CARD-01 card fixtures:', check())
