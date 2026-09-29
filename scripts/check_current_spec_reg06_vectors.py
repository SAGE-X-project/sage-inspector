"""Audit bounded eip155 deployment fixtures without granting conformance."""

import base64
import hashlib
import json
import re

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/reg06-scenarios.json'
IDS = ('REG-06-P', 'REG-06-N01', 'REG-06-N02',
       'REG-06-N03', 'REG-06-N04')
TRACKS = ('runtime', 'deployment_review')
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CHAPTER_SHA = '2f7e5468bf87e7a402c7853584fca8e345b5055a0625f7068a71e80e6321eb02'
FIELDS = ('chain_id', 'registry_address', 'deployed_code_hash',
          'upgrade_policy', 'abi_mapping', 'operator_scopes',
          'transaction_authorization', 'finalized_node',
          'measured_cost_latency')


def decision(inp):
    trusted = inp['trusted_configuration']
    candidate = inp['candidate']
    observed = inp['observation']
    if set(candidate) != set(FIELDS) or candidate != trusted:
        return 'REJECT'
    if not re.fullmatch(r'[1-9][0-9]{0,31}', candidate['chain_id']):
        return 'REJECT'
    if not re.fullmatch(r'0x[0-9a-f]{40}', candidate['registry_address']):
        return 'REJECT'
    if not re.fullmatch(r'[0-9a-f]{64}', candidate['deployed_code_hash']):
        return 'REJECT'
    abi = candidate['abi_mapping']
    if abi != {'sections': ['1', '2', '3', '4', '5'],
               'authenticated_reads': True,
               'authenticated_writes': True}:
        return 'REJECT'
    if (not candidate['upgrade_policy'] or not candidate['operator_scopes']
            or candidate['transaction_authorization']['chain_id'] != candidate['chain_id']
            or not candidate['finalized_node']['ready']
            or not candidate['measured_cost_latency']):
        return 'REJECT'
    if (observed['source'] != candidate['finalized_node']['identity']
            or observed['finalized'] is not True
            or observed['record_block_hash'] != observed['keys_block_hash']):
        return 'REJECT'
    return 'ACCEPT'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC
            and suite['source_sha256'] == CHAPTER_SHA
            and manifest['source_sha256']['spec/09-registry.md'] == CHAPTER_SHA
            and tuple(row['id'] for row in suite['cases']) == IDS
            and suite['scope'] ==
                'synthetic deployment and finalized reads; no deployed contract or transaction',
            'pinned REG-06 source and bounded case inventory')
    rows = {row['id']: row for row in suite['cases']}
    positive = rows['REG-06-P']['input']
    require(set(positive['candidate']) == set(FIELDS)
            and positive['candidate'] == positive['trusted_configuration']
            and decision(positive) == 'ACCEPT',
            'complete synthetic deployment control')
    for ident, field in (('REG-06-N01', 'registry_address'),
                         ('REG-06-N02', 'deployed_code_hash'),
                         ('REG-06-N03', 'abi_mapping')):
        inp = rows[ident]['input']
        changed = [key for key in FIELDS
                   if inp['candidate'][key] != positive['candidate'][key]]
        require(changed == [field] and
                inp['trusted_configuration'] == positive['trusted_configuration']
                and inp['observation'] == positive['observation']
                and decision(inp) == 'REJECT',
                'isolated REG-06 deployment defect: ' + ident)
    inconsistent = rows['REG-06-N04']['input']
    require(inconsistent['candidate'] == positive['candidate']
            and inconsistent['trusted_configuration'] == positive['trusted_configuration']
            and inconsistent['observation']['finalized'] is True
            and inconsistent['observation']['record_block_hash'] !=
                inconsistent['observation']['keys_block_hash']
            and decision(inconsistent) == 'REJECT',
            'same finalized block required for record and keys')
    for ident in IDS:
        row = rows[ident]
        verdict = 'ACCEPT' if ident == 'REG-06-P' else 'REJECT'
        require(decision(row['input']) == verdict and row['expected'] ==
                {'verdict': verdict, 'output': {}, 'effects': {}},
                'REG-06 expected outcome: ' + ident)
        for track in TRACKS:
            relative = ('vectors/0.10.0/current-spec/' + ident +
                        '-' + track + '.json')
            fixture = load((root / relative).read_bytes())
            require(fixture['schema_version'] == 1 and
                    fixture['spec_revision'] == SPEC and
                    fixture['id'] == ident and fixture['track'] == track and
                    fixture['expected'] == row['expected'],
                    'REG-06 track fixture identity: ' + ident + '/' + track)
            if track == 'runtime':
                require(fixture['input'] == {
                            'operation': 'sage.registry.eip155.binding.check',
                            'input': row['input']},
                        'REG-06 core runtime request: ' + ident)
            else:
                require(fixture['input']['required'] == list(FIELDS) and
                        fixture['input']['trusted_configuration'] ==
                        row['input']['trusted_configuration'] and
                        fixture['input']['candidate'] == row['input']['candidate'] and
                        fixture['input']['observation'] == row['input']['observation'],
                        'REG-06 separate deployment review: ' + ident)
    control = suite['claim_control']
    claim = control['claim']
    require(set(claim) == {'registryId', 'agentId', 'controller',
                           'keys', 'services', 'salt'} and
            claim['registryId'] == 'eip155:1:' + positive['candidate']['registry_address']
            and re.fullmatch(r'[A-Za-z0-9._-]{1,64}', claim['agentId'])
            and claim['agentId'] not in ('.', '..')
            and claim['controller'] == control['commit_account']
            and len(base64.urlsafe_b64decode(claim['salt'] + '==')) == 32
            and base64.urlsafe_b64encode(
                base64.urlsafe_b64decode(claim['salt'] + '==')).decode().rstrip('=') ==
                claim['salt'] and any(key['alg'] == 'ed25519'
                                      for key in claim['keys']),
            'canonical claim fields, salt, controller and signing algorithm')
    canonical = json.dumps(claim, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False).encode()
    require(canonical.isascii() and control['canonical_utf8_hex'] == canonical.hex()
            and control['commitment_sha256'] ==
                hashlib.sha256(b'sage-claim-0.10.0\0' + canonical).hexdigest()
            and control['valid_reveal_block'] == control['commit_block'] + 1
            and control['last_reveal_block'] == control['commit_block'] + 256
            and control['late_reveal_block'] == control['commit_block'] + 257
            and control['other_account'] != control['commit_account']
            and control['activation_separate'] is True,
            'bounded claim hash, account, window, and activation control')
    return len(IDS), len(TRACKS), control['commitment_sha256']


if __name__ == '__main__':
    print(check())
