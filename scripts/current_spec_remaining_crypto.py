"""Bounded review decisions for previously unbound cryptographic cases.

Fixed signature vectors are independent controls. Host verdicts remain partial
until an identified implementation executes those vectors.
"""

import hashlib
import json
import re

from current_spec_catalog import ROOT, require


IDS = tuple(
    f'CRYPTO-01-{suffix}' for suffix in ('P', 'N01', 'N02', 'N03', 'N04')
) + tuple(
    f'CRYPTO-02-{suffix}' for suffix in ('P', 'N01', 'N02', 'N03', 'N04', 'N05')
) + tuple(
    f'CRYPTO-03-{suffix}' for suffix in ('P', 'N01', 'N02', 'N03', 'N04')
) + tuple(
    f'CRYPTO-04-{suffix}' for suffix in ('P', 'N01', 'N02', 'N03')
) + tuple(
    f'CRYPTO-05-{suffix}' for suffix in ('P', 'N01', 'N02', 'N03')
)
VECTOR_SHA256 = '8b7b202db497bb40a65b64f62a4afc0a3bd0a24b624fd76557d69f4b211bdd26'
VECTOR_CASES = {
    'CRYPTO-02-P': ('ed25519-rfc8032', 'p256-valid', 'secp256k1-valid'),
    'CRYPTO-02-N01': ('ed25519-truncated', 'p256-truncated',
                      'secp256k1-truncated'),
    'CRYPTO-02-N02': ('p256-der', 'secp256k1-der'),
    'CRYPTO-02-N03': ('p256-off-curve', 'secp256k1-off-curve'),
    'CRYPTO-02-N04': ('ed25519-scalar-L',),
    'CRYPTO-02-N05': ('ed25519-mixed-A', 'ed25519-mixed-R'),
}
SECP_ORDER = int(
    'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)


def fixed_vectors():
    raw = (ROOT / 'vectors/0.10.0/jcs-signatures.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == VECTOR_SHA256,
            'pinned independent signature vectors')
    return {row['id']: row for row in json.loads(raw)['cases']}


def sample(ident):
    if ident.startswith('CRYPTO-01'):
        result = {'algorithm': 'ed25519', 'key_kind': 'Ed25519',
                  'public_key_bytes': 32, 'signature_bytes': 64,
                  'active_signing_key': True, 'accepted': True}
        if ident.endswith('-N01'):
            result.update(algorithm='rsa-pss-sha256', key_kind='RSA',
                          public_key_bytes=256, accepted=False)
        elif ident.endswith('-N02'):
            result.update(algorithm='unknown-suite', accepted=False)
        elif ident.endswith('-N03'):
            result.update(algorithm='ecdsa-p256-sha256',
                          key_kind='secp256k1', public_key_bytes=65,
                          accepted=False)
        elif ident.endswith('-N04'):
            result.update(algorithm='es256k', key_kind='secp256k1',
                          public_key_bytes=65, accepted=False)
        return result
    if ident.startswith('CRYPTO-02'):
        vectors = fixed_vectors()
        return {'reports': [{'id': name,
                             'verdict': vectors[name]['expected']['verdict']}
                            for name in VECTOR_CASES[ident]]}
    if ident.startswith('CRYPTO-03'):
        result = {'curve': 'secp256k1', 'r': 1, 's': 1,
                  'recovery_byte': 0, 'accepted': True}
        if ident.endswith('-N01'):
            result.update(s=SECP_ORDER - 1, accepted=False)
        elif ident.endswith('-N02'):
            result.update(r=0, accepted=False)
        elif ident.endswith('-N03'):
            result.update(s=0, accepted=False)
        elif ident.endswith('-N04'):
            result.update(recovery_byte=2, accepted=False)
        return result
    if ident.startswith('CRYPTO-04'):
        key_url = 'did:sage:web:agents.example.com:alice#key-1'
        result = {'key_url': key_url,
                  'resolved_key_url': key_url,
                  'domain': 'intent', 'expected_domain': 'intent',
                  'public_bytes_match': True, 'key_active': True,
                  'accepted': True}
        if ident.endswith('-N01'):
            result.update(key_url='did:sage:web:agents.example.com:alice',
                          accepted=False)
        elif ident.endswith('-N02'):
            result.update(key_url='did:sage:web:agents.example.com:alice#key-2',
                          accepted=False)
        elif ident.endswith('-N03'):
            result.update(domain='result', accepted=False)
        return result
    result = {'plugin_key_read_grants': [],
              'ephemeral_public_ids': ['eph-1', 'eph-2'],
              'secret_log_events': [],
              'comparison_kind': 'constant_time',
              'signer_domain_bound': True,
              'erasure_claimed': False, 'erasure_proven': False,
              'accepted': True}
    if ident.endswith('-N01'):
        result.update(plugin_key_read_grants=['grant-1'], accepted=False)
    elif ident.endswith('-N02'):
        result.update(ephemeral_public_ids=['eph-1', 'eph-1'],
                      accepted=False)
    elif ident.endswith('-N03'):
        result.update(erasure_claimed=True, accepted=False)
    return result


def check(ident, evidence):
    if ident not in IDS or type(evidence) is not dict or \
            set(evidence) != set(sample(ident)):
        return False
    if ident.startswith('CRYPTO-01'):
        if type(evidence['accepted']) is not bool or \
                type(evidence['active_signing_key']) is not bool or \
                any(type(evidence[key]) is not int for key in
                    ('public_key_bytes', 'signature_bytes')):
            return False
        suites = {'ed25519': ('Ed25519', 32, 64),
                  'ecdsa-p256-sha256': ('P-256', 65, 64),
                  'sage-secp256k1-keccak256': ('secp256k1', 65, 65)}
        expected = suites.get(evidence['algorithm'])
        accepted = (expected == (evidence['key_kind'],
                                 evidence['public_key_bytes'],
                                 evidence['signature_bytes']) and
                    evidence['active_signing_key'])
        return (evidence['accepted'] is accepted and
                accepted is ident.endswith('-P'))
    if ident.startswith('CRYPTO-02'):
        vectors = fixed_vectors()
        reports = evidence['reports']
        if type(reports) is not list or \
                [row.get('id') for row in reports if type(row) is dict] != \
                list(VECTOR_CASES[ident]) or len(reports) != len(VECTOR_CASES[ident]):
            return False
        return all(type(row) is dict and set(row) == {'id', 'verdict'} and
                   vectors[row['id']]['operation'] == 'signature.verify' and
                   row['verdict'] == vectors[row['id']]['expected']['verdict']
                   for row in reports)
    if ident.startswith('CRYPTO-03'):
        if any(type(evidence[key]) is not int for key in
               ('r', 's', 'recovery_byte')) or \
                type(evidence['accepted']) is not bool:
            return False
        valid = (evidence['curve'] == 'secp256k1' and
                 1 <= evidence['r'] < SECP_ORDER and
                 1 <= evidence['s'] <= SECP_ORDER // 2 and
                 evidence['recovery_byte'] in (0, 1))
        return (evidence['accepted'] is valid and
                valid is ident.endswith('-P'))
    if ident.startswith('CRYPTO-04'):
        if any(type(evidence[key]) is not bool for key in
               ('public_bytes_match', 'key_active', 'accepted')):
            return False
        valid = (type(evidence['key_url']) is str and
                 len(evidence['key_url'].encode()) <= 289 and
                 re.fullmatch(r'did:sage:web:[a-z0-9.-]+:'
                              r'[A-Za-z0-9._-]{1,64}#'
                              r'[A-Za-z0-9_-]{1,32}',
                              evidence['key_url']) is not None and
                 evidence['key_url'] == evidence['resolved_key_url'] and
                 evidence['domain'] == evidence['expected_domain'] and
                 evidence['public_bytes_match'] and evidence['key_active'])
        return (evidence['accepted'] is valid and
                valid is ident.endswith('-P'))
    if any(type(evidence[key]) is not list for key in
           ('plugin_key_read_grants', 'ephemeral_public_ids',
            'secret_log_events')) or \
            any(type(evidence[key]) is not bool for key in
                ('signer_domain_bound', 'erasure_claimed',
                 'erasure_proven', 'accepted')):
        return False
    valid = (not evidence['plugin_key_read_grants'] and
             len(evidence['ephemeral_public_ids']) >= 2 and
             len(set(evidence['ephemeral_public_ids'])) ==
             len(evidence['ephemeral_public_ids']) and
             not evidence['secret_log_events'] and
             evidence['comparison_kind'] == 'constant_time' and
             evidence['signer_domain_bound'] and
             not evidence['erasure_claimed'])
    return (evidence['accepted'] is valid and valid is ident.endswith('-P'))
