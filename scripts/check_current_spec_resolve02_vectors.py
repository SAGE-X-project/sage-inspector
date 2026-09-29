"""Audit bounded fresh resolution cases without claiming source authentication."""

import copy
import json

from check_current_spec_reg08_vectors import decision as web_decision
from check_current_spec_resolve01_vectors import decision as projection_decision
from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/resolve02-scenarios.json'
REGISTRY_SOURCE = 'vectors/0.10.0/reg08-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CHAPTER_SHA = '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c'
IDS = ('RESOLVE-02-P', 'RESOLVE-02-N01', 'RESOLVE-02-N02',
       'RESOLVE-02-N03', 'RESOLVE-02-N04', 'RESOLVE-02-N05')


def decision(inp):
    if web_decision(inp) != 'ACCEPT':
        return 'REJECT'
    record = inp['response']['body']['record']
    if (not isinstance(record, dict) or
            set(record) != {'id', 'controller', 'keys', 'services', 'state', 'version'} or
            record['state'] not in ('created', 'active', 'deactivated') or
            record['id'] != inp['did'] or
            not record['version'].isdigit() or record['version'].startswith('0') or
            not 1 <= int(record['version']) <= 18446744073709551615 or
            int(record['version']) < inp['local_version_floor'] or
            not 1 <= len(record['keys']) <= 128 or
            len(record['services']) > 16):
        return 'REJECT'
    signing_urls = {record['id'] + '#' + key['name'] for key in record['keys']
                    if key.get('alg') != 'x25519' and key.get('state') == 'accepted'}
    for key in record['keys']:
        if set(key) not in ({'name', 'alg', 'key', 'proof', 'state'},
                           {'name', 'alg', 'key', 'proof', 'state', 'expires'}):
            return 'REJECT'
        proof = key['proof']
        if (not isinstance(proof, dict) or set(proof) != {'signer', 'value'} or
                not proof['value'] or key['state'] not in ('accepted', 'revoked')):
            return 'REJECT'
        if key['alg'] == 'x25519':
            if proof['signer'] not in signing_urls:
                return 'REJECT'
        elif proof['signer'] != record['id'] + '#' + key['name']:
            return 'REJECT'
    if (record['state'] == 'active' and
            not any(key['state'] == 'accepted' and key['alg'] != 'x25519'
                    for key in record['keys'])):
        return 'REJECT'
    return 'ACCEPT'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    registry_raw = (root / REGISTRY_SOURCE).read_bytes()
    source = load(registry_raw)['cases'][0]['input']
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == CHAPTER_SHA and
            manifest['source_sha256']['spec/10-resolution.md'] == CHAPTER_SHA and
            suite['registry_source_sha256'] == sha(registry_raw) and
            suite['scope'] == 'synthetic configured web observation; no live TLS, operator provenance, signature revalidation, or blockchain finality' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'pinned RESOLVE-02 sources and bounded case inventory')
    positive = suite['cases'][0]
    inp, output = positive['input'], positive['expected']['output']
    record = inp['response']['body']['record']
    require(inp == dict(source, local_version_floor=1) and decision(inp) == 'ACCEPT' and
            set(output) == {'didDocument', 'didDocumentMetadata',
                            'didResolutionMetadata'} and
            projection_decision(record, output['didDocument']) == 'ACCEPT' and
            output['didDocumentMetadata'] == {
                'deactivated': False, 'versionId': record['version'],
                'sage': {'state': record['state'], 'controller': record['controller'],
                         'observedAt': inp['response']['body']['issued'],
                         'source': inp['policy']['configured_origin'],
                         'observedTime': inp['trusted_now']}} and
            output['didResolutionMetadata'] == {'contentType': 'application/did+json'},
            'fresh authoritative lookup and complete envelope shape')
    for index, row in enumerate(suite['cases']):
        ident = row['id']
        verdict = 'ACCEPT' if index == 0 else 'REJECT'
        expected = {'verdict': verdict,
                    'output': output if index == 0 else {}, 'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(decision(row['input']) == verdict and
                row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.did.resolve',
                                      'input': row['input']},
                            'expected': expected},
                'RESOLVE-02 case contract: ' + ident)
    unknown, malformed, stale, unauthenticated, cached = [
        row['input'] for row in suite['cases'][1:]]
    require(unknown['response']['status'] == 404 and
            unknown['response']['body']['record'] is None and
            malformed['response']['body']['record']['state'] == 'deactivated' and
            'proof' not in malformed['response']['body']['record']['keys'][0] and
            stale['trusted_now'] == inp['response']['body']['expires'] and
            unauthenticated['request']['authenticated_tls_origin'] is None and
            cached['response']['source'] == 'intermediary-positive-cache',
            'five isolated resolution failure conditions')
    inactive = copy.deepcopy(inp)
    inactive_record = inactive['response']['body']['record']
    inactive_record['state'] = 'deactivated'
    inactive['response']['body_bytes'] = len(json.dumps(
        inactive['response']['body'], separators=(',', ':')).encode())
    require(decision(inactive) == 'ACCEPT',
            'well-formed deactivated record still resolves for inspection')
    for name, mutate in (
        ('missing-state', lambda x: x['response']['body']['record'].pop('state')),
        ('wrong-id', lambda x: x['response']['body']['record'].update(id='did:sage:web:agents.example.com:bob')),
        ('peer-resolver', lambda x: x['request'].update(url='https://peer.example/resolve')),
        ('reused-version', lambda x: x['response']['body']['record'].update(version='0')),
        ('version-rollback', lambda x: x.update(local_version_floor=2)),
    ):
        control = copy.deepcopy(inp)
        mutate(control)
        control['response']['body_bytes'] = len(json.dumps(
            control['response']['body'], separators=(',', ':')).encode())
        require(decision(control) == 'REJECT', 'supplemental fail-closed control: ' + name)
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(all(any(binding['id'] == ident and binding['coverage'] == 'partial' and
                    binding['fixture_sha256'] == sha((root / 'vectors/0.10.0/current-spec' /
                                                     (ident + '.json')).read_bytes())
                    for binding in bindings['bindings']) for ident in IDS),
            'partial runtime case bindings')
    return len(IDS), 6


if __name__ == '__main__':
    print(check())
