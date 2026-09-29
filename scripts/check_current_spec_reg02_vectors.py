"""Independently audit fixed Registry selection and immutable-key cases."""

import copy
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from check_current_spec_reg01_vectors import decoded, proof_input
from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/reg02-scenarios.json'
IDS = ('REG-02-P', 'REG-02-N01', 'REG-02-N02', 'REG-02-N03')
CONTROLS = ('no-kem', 'revoked-first', 'expired-first')
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
DID = 'did:sage:web:agents.example.com:alice'
NOW = 1700000000


def proven(record, key):
    signer_url = key['proof']['signer']
    require(signer_url.startswith(record['id'] + '#'), 'same-record proof signer')
    signer = next(k for k in record['keys']
                  if k['name'] == signer_url.split('#', 1)[1])
    require(signer['alg'] == 'ed25519', 'proof signer role')
    try:
        Ed25519PublicKey.from_public_bytes(decoded(signer['key'])).verify(
            decoded(key['proof']['value']), proof_input(record, key))
    except InvalidSignature:
        return False
    return True


def eligible_kems(record):
    return [key for key in record['keys'] if key['alg'] == 'x25519'
            and key['state'] == 'accepted' and NOW < key.get('expires', NOW + 1)]


def check(root=ROOT):
    source_raw = (root / 'vectors/0.10.0/registry-records.json').read_bytes()
    original = {row['id']: row for row in load(source_raw)['cases']}
    suite = load((root / SOURCE).read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC
            and suite['source_sha256'] == sha(source_raw)
            and tuple(row['id'] for row in suite['cases']) == IDS
            and tuple(row['name'] for row in suite['supplemental']) == CONTROLS,
            'pinned REG-02 sources and case identity')
    rows = {row['id']: row for row in suite['cases']}
    extras = {row['name']: row for row in suite['supplemental']}
    first = rows['REG-02-P']['input']
    require(first == original['kem-select-first-ascii']['input']
            and first['record']['id'] == DID and first['now'] == NOW
            and [key['name'] for key in eligible_kems(first['record'])] ==
                ['kem-0', 'kem-1']
            and all(proven(first['record'], key)
                    for key in first['record']['keys']),
            'two independently proven eligible KEMs')
    damaged = rows['REG-02-N01']['input']
    require(damaged['now'] == NOW and
            damaged['record']['keys'][1:] == first['record']['keys'][1:] and
            damaged['record']['keys'][0]['name'] == 'kem-0' and
            damaged['record']['keys'][0]['key'] ==
                first['record']['keys'][0]['key'] and
            not proven(damaged['record'], damaged['record']['keys'][0]) and
            all(proven(damaged['record'], key)
                for key in damaged['record']['keys'][1:]) and
            len(eligible_kems(damaged['record'])) == 2,
            'only selected earliest KEM proof is invalid; no later fallback')
    revoked = rows['REG-02-N02']['input']
    require(revoked == original['authenticate-historical-False']['input']
            and revoked['keyid'] == DID + '#signing-1'
            and revoked['alg'] == 'ed25519'
            and revoked['sender'] == revoked['expected_peer'] == DID
            and all(proven(revoked['record'], key)
                    for key in revoked['record']['keys'])
            and next(key for key in revoked['record']['keys']
                     if key['name'] == 'signing-1')['state'] == 'revoked'
            and next(key for key in revoked['record']['keys']
                     if key['name'] == 'signing-2')['state'] == 'accepted',
            'revoked named signer with valid historical proof and accepted alternative')
    transition = rows['REG-02-N03']['input']
    before = transition['previous_record']
    after = transition['candidate_record']
    unchanged = copy.deepcopy(after)
    unchanged['keys'][0] = before['keys'][0]
    require(before == first['record'] and after['version'] == '2'
            and unchanged == {**before, 'version': '2'}
            and transition['keyid'] == DID + '#kem-0'
            and transition['now'] == NOW
            and before['keys'][0]['key'] != after['keys'][0]['key']
            and before['keys'][0]['alg'] == after['keys'][0]['alg'] == 'x25519'
            and all(proven(after, key) for key in after['keys'])
            and len(decoded(after['keys'][0]['key'])) == 32,
            'new valid proof and version cannot replace an existing named key')
    for name, source_id in (('no-kem', 'kem-select-no-kem'),
                            ('revoked-first', 'kem-select-first-revoked'),
                            ('expired-first', 'kem-select-first-expired')):
        require(extras[name]['input'] == original[source_id]['input'] and
                extras[name]['expected'] == original[source_id]['expected']['verdict'],
                'supplemental source identity: ' + name)
    require(not eligible_kems(extras['no-kem']['input']['record'])
            and [key['alg'] for key in extras['no-kem']['input']['record']['keys']]
                == ['ed25519']
            and [key['name'] for key in eligible_kems(
                extras['revoked-first']['input']['record'])] == ['kem-1']
            and [key['name'] for key in eligible_kems(
                extras['expired-first']['input']['record'])] == ['kem-1'],
            'signing/KEM separation and revoked or expired predecessor')
    for ident in IDS:
        row = rows[ident]
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': row['operation'],
                                      'input': row['input']},
                            'expected': row['expected']},
                'REG-02 runtime fixture contract: ' + ident)
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(manifest['spec_revision'] == SPEC and
            manifest['source_sha256']['spec/09-registry.md'] ==
                '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02'
            and manifest['source_sha256']['spec/11-registries.md'] ==
                'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
            'current normative Registry and algorithm chapters')
    return len(IDS), len(CONTROLS)


if __name__ == '__main__':
    print('Verified REG-02 cases and controls:', check())
