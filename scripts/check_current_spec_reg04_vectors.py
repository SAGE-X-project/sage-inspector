"""Independently audit Registry proof and KEM endorsement boundaries."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from check_current_spec_reg01_vectors import decoded
from check_current_spec_reg02_vectors import proven
from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/reg04-scenarios.json'
IDS = ('REG-04-P', 'REG-04-N01', 'REG-04-N02', 'REG-04-N03',
       'REG-04-N04')
CONTROLS = ('historical-message', 'historical-new-endorsement',
            'valid-pop', 'wrong-registry-signature')
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
DID = 'did:sage:web:agents.example.com:alice'


def signature_valid(inp):
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(inp['public_key_hex']))
    try:
        public.verify(bytes.fromhex(inp['signature_hex']),
                      bytes.fromhex(inp['message_hex']))
    except InvalidSignature:
        return False
    return True


def check(root=ROOT):
    source_raw = (root / 'vectors/0.10.0/registry-records.json').read_bytes()
    original = {row['id']: row for row in load(source_raw)['cases']}
    suite = load((root / SOURCE).read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC
            and suite['source_sha256'] == sha(source_raw)
            and tuple(row['id'] for row in suite['cases']) == IDS
            and tuple(row['name'] for row in suite['supplemental']) == CONTROLS,
            'pinned REG-04 sources and case identity')
    rows = {row['id']: row for row in suite['cases']}
    extras = {row['name']: row for row in suite['supplemental']}
    historical = load(bytes.fromhex(rows['REG-04-P']['input']['record_hex']))
    source_historical = original['record-historical-False']['input']
    require(rows['REG-04-P']['input'] == source_historical and
            historical['state'] == 'active' and
            all(proven(historical, key) for key in historical['keys'])
            and historical['keys'][0]['alg'] == 'x25519'
            and historical['keys'][0]['proof']['signer'] == DID + '#signing-1'
            and historical['keys'][1]['state'] == 'revoked'
            and historical['keys'][2]['state'] == 'accepted'
            and historical['keys'][2]['alg'] == 'ed25519',
            'retained KEM proof verifies using revoked historical signer')
    pop = original['pop-current']['input']
    copied = rows['REG-04-N01']['input']
    require(rows['REG-04-N01']['operation'] ==
                'sage.registry.pop.domain.verify'
            and {k: v for k, v in copied.items() if k != 'registry_id'} == pop
            and copied['registry_id'] == 'web:other.example'
            and pop['did'] == DID,
            'same signing PoP presented under a different registry ID')
    valid_sig = extras['valid-pop']['input']
    wrong_sig = extras['wrong-registry-signature']['input']
    require(valid_sig == original['signing-1-signature-valid']['input']
            and wrong_sig == original['signing-1-signature-registry']['input']
            and valid_sig['signature_hex'] == wrong_sig['signature_hex']
            and valid_sig['public_key_hex'] == wrong_sig['public_key_hex']
            and bytes.fromhex(valid_sig['message_hex']).startswith(
                b'sage-pop-0.10.0')
            and signature_valid(valid_sig) and not signature_valid(wrong_sig),
            'same valid signature fails over changed registry challenge')
    transfer = rows['REG-04-N02']['input']
    before = transfer['previous_record']
    after = transfer['candidate_record']
    require(before == original['authenticate-valid']['input']['record']
            and transfer['actor'] == before['controller']
            and transfer['operation'] == 'change-controller'
            and transfer['expected_version'] == before['version'] == '1'
            and after['version'] == '2'
            and after['controller'] != before['controller']
            and {**after, 'controller': before['controller'],
                 'version': before['version']} == before
            and all(proven(before, key) for key in before['keys'])
            and all(proven(after, key) for key in after['keys']),
            'unchanged valid PoPs cannot authorize controller transfer')
    claimed = load(bytes.fromhex(rows['REG-04-N03']['input']['record_hex']))
    require({**claimed['keys'][0], 'proof': before['keys'][0]['proof']}
            == before['keys'][0] and
            claimed['keys'][0]['proof']['signer'] == DID + '#kem-1'
            and claimed['keys'][0]['alg'] == 'x25519'
            and {**claimed, 'keys': before['keys']} == before
            and len(decoded(claimed['keys'][0]['proof']['value'])) == 64,
            'KEM cannot claim Ed25519 signing role for its own proof')
    short = load(bytes.fromhex(rows['REG-04-N04']['input']['record_hex']))
    require({**short, 'keys': before['keys']} == before
            and {**short['keys'][0], 'key': before['keys'][0]['key'],
                 'proof': before['keys'][0]['proof']} == before['keys'][0]
            and len(decoded(short['keys'][0]['key'])) == 31
            and proven(short, short['keys'][0])
            and proven(short, short['keys'][1]),
            'invalid X25519 length despite valid endorsement signature')
    for name, source_id in (
            ('historical-message', 'authenticate-historical-False'),
            ('historical-new-endorsement', 'record-new-endorsement-False'),
            ('valid-pop', 'signing-1-signature-valid'),
            ('wrong-registry-signature', 'signing-1-signature-registry')):
        require(extras[name]['input'] == original[source_id]['input'] and
                extras[name]['expected'] == original[source_id]['expected']['verdict'],
                'supplemental source identity: ' + name)
    require(extras['historical-message']['input']['keyid'] == DID + '#signing-1'
            and extras['historical-new-endorsement']['input']['mode'] ==
                'add-kem',
            'historical signer cannot authenticate or endorse a new key')
    for ident in IDS:
        row = rows[ident]
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': row['operation'],
                                      'input': row['input']},
                            'expected': row['expected']},
                'REG-04 runtime fixture contract: ' + ident)
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(manifest['spec_revision'] == SPEC and
            manifest['source_sha256']['spec/09-registry.md'] ==
                '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02'
            and manifest['source_sha256']['spec/11-registries.md'] ==
                'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
            'pinned normative Registry and algorithm chapters')
    return len(IDS), len(CONTROLS)


if __name__ == '__main__':
    print('Verified REG-04 cases and controls:', check())
