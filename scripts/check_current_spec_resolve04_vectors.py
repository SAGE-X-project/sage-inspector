"""Independently audit exact DID key dereference and fresh record gates."""

import copy
import json
import re

from check_current_spec_resolve02_vectors import decision as resolver_decision
from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/resolve04-scenarios.json'
REGISTRY_SOURCE = 'vectors/0.10.0/reg08-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CHAPTER_SHA = '12466dfeec90465c3fe014700972549d76917c7db87c207ce28d63867fbbe55c'
IDS = ('RESOLVE-04-P', 'RESOLVE-04-N01', 'RESOLVE-04-N02',
       'RESOLVE-04-N03', 'RESOLVE-04-N04', 'RESOLVE-04-N05')


def classify(inp):
    observation = inp['observation']
    if resolver_decision(dict(observation, local_version_floor=1)) != 'ACCEPT':
        return 'record.not-current'
    record = observation['response']['body']['record']
    did, url = record['id'], inp['key_url']
    if (not isinstance(url, str) or not url.isascii() or
            len(url.encode()) > 289 or url.count('#') != 1):
        return 'sig.malformed'
    base, name = url.split('#')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', name):
        return 'sig.malformed'
    if (base != did or inp['expected_peer'] != did or
            record['state'] != 'active'):
        return 'sig.binding'
    key = next((item for item in record['keys'] if item['name'] == name), None)
    if key is None:
        return 'key.not-in-record'
    if key['state'] == 'revoked':
        return 'key.revoked'
    if 'expires' in key and observation['trusted_now'] >= key['expires']:
        return 'key.expired'
    relationship = inp['required_relationship']
    if relationship not in ('authentication', 'assertionMethod', 'keyAgreement'):
        return 'key.wrong-relationship'
    if (key['alg'] == 'x25519') != (relationship == 'keyAgreement'):
        return 'key.wrong-relationship'
    return 'ACCEPT'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    raw = (root / REGISTRY_SOURCE).read_bytes()
    source = load(raw)['cases'][0]['input']
    record = source['response']['body']['record']
    did = record['id']
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['source_sha256'] == CHAPTER_SHA and
            manifest['source_sha256']['spec/10-resolution.md'] == CHAPTER_SHA and
            suite['registry_source_sha256'] == sha(raw) and
            suite['scope'] == 'synthetic current web observation; no live TLS, Registry proof revalidation, or signature trial' and
            tuple(row['id'] for row in suite['cases']) == IDS,
            'pinned RESOLVE-04 sources and bounded case inventory')
    positive = suite['cases'][0]
    good = positive['input']
    method = positive['expected']['output']['verificationMethod']
    kem = next(row for row in record['keys'] if row['name'] == 'kem-1')
    require(good == {'observation': source, 'key_url': did + '#kem-1',
                     'required_relationship': 'keyAgreement',
                     'expected_peer': did} and
            classify(good) == 'ACCEPT' and
            method == {'id': did + '#kem-1', 'type': 'JsonWebKey2020',
                       'controller': did,
                       'publicKeyJwk': {'kty': 'OKP', 'crv': 'X25519',
                                        'x': kem['key']}},
            'exact agreement method and current authority')
    expected_causes = ('ACCEPT', 'sig.malformed', 'key.not-in-record',
                       'key.revoked', 'key.not-in-record',
                       'key.wrong-relationship')
    for index, row in enumerate(suite['cases']):
        ident = row['id']
        verdict = 'ACCEPT' if index == 0 else 'REJECT'
        expected = {'verdict': verdict,
                    'output': {'verificationMethod': method} if index == 0 else {},
                    'effects': {}}
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ident + '.json')).read_bytes())
        require(classify(row['input']) == expected_causes[index] and
                row['expected'] == expected and
                fixture == {'schema_version': 1, 'spec_revision': SPEC,
                            'id': ident, 'track': 'runtime',
                            'input': {'operation': 'sage.did.key.dereference',
                                      'input': row['input']},
                            'expected': expected},
                'RESOLVE-04 case contract: ' + ident)
    missing, unknown, revoked, service, wrong = [row['input']
                                                  for row in suite['cases'][1:]]
    require(missing == dict(good, key_url=did) and
            unknown == dict(good, key_url=did + '#not-registered') and
            revoked['observation']['response']['body']['record']['keys'][0]['state'] == 'revoked' and
            service == dict(good, key_url=did + '#api') and
            wrong == dict(good, required_relationship='authentication'),
            'isolated fragment, revocation, service, and relationship defects')
    for name, mutate, cause in (
        ('signing-authentication', lambda x: x.update(
            key_url=did + '#signing-1', required_relationship='authentication'), 'ACCEPT'),
        ('expired-key', lambda x: x['observation']['response']['body']['record']['keys'][0].update(expires=102), 'key.expired'),
        ('wrong-peer', lambda x: x.update(expected_peer=did + ':other'), 'sig.binding'),
        ('percent-encoding', lambda x: x.update(key_url=did + '#kem%2D1'), 'sig.malformed'),
        ('stale-source', lambda x: x['observation'].update(trusted_now=105), 'record.not-current'),
        ('inactive-record', lambda x: x['observation']['response']['body']['record'].update(state='deactivated'), 'sig.binding'),
    ):
        control = copy.deepcopy(good)
        mutate(control)
        body = control['observation']['response']['body']
        control['observation']['response']['body_bytes'] = len(
            json.dumps(body, separators=(',', ':')).encode())
        require(classify(control) == cause, 'supplemental key control: ' + name)
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(all(any(binding['id'] == ident and binding['coverage'] == 'partial' and
                    binding['fixture_sha256'] == sha((root / 'vectors/0.10.0/current-spec' /
                                                     (ident + '.json')).read_bytes())
                    for binding in bindings['bindings']) for ident in IDS),
            'partial runtime bindings')
    return len(IDS), 6


if __name__ == '__main__':
    print(check())
