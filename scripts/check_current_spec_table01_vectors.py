"""Audit bounded SAGE-local registry governance without claiming adoption."""

import copy
import re

from current_spec_catalog import ROOT, load, require, sha


SOURCE = 'vectors/0.10.0/table01-scenarios.json'
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
CHAPTER_SHA = 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4'
OVERVIEW_SHA = '82493ba53f38cc783a2e76ffab3a70dc069b6ac3e534c7422840369fc90d9978'
IDS = ('TABLE-01-P', 'TABLE-01-N01', 'TABLE-01-N02', 'TABLE-01-N03')
TRACKS = ('runtime', 'document_review')
SNAPSHOT = {
    'signature_algorithms': [
        {'value': 'ed25519', 'digest': 'none', 'status': 'mandatory'},
        {'value': 'sage-secp256k1-keccak256', 'digest': 'Keccak-256',
         'status': 'optional'},
        {'value': 'ecdsa-p256-sha256', 'digest': 'SHA-256',
         'status': 'optional'}],
    'domain_labels': [
        {'value': 'sage-pop-0.10.0', 'meaning': 'Registry key possession',
         'status': 'assigned'},
        {'value': 'sage-pop-v1', 'meaning': 'Legacy Registry key possession',
         'status': 'obsolete'}],
    'private_signature_prefix': 'x-',
    'wire_version': '0.10.0'}


def decision(inp):
    if (inp['trusted_registry'] != SNAPSHOT or
            inp['candidate_registry'] != SNAPSHOT):
        return 'REJECT'
    algorithm = inp['observed_wire_algorithm']
    if not isinstance(algorithm, str) or inp['wire_scope'] not in ('internal', 'external'):
        return 'REJECT'
    assigned = {row['value'] for row in SNAPSHOT['signature_algorithms']}
    if algorithm in assigned:
        return 'ACCEPT'
    if algorithm.startswith('x-') and inp['wire_scope'] == 'internal':
        return 'ACCEPT'
    return 'REJECT'


def proposal_decision(proposal):
    issue = proposal.get('issue')
    if not isinstance(issue, dict) or set(issue) != {
            'repository', 'registry', 'value', 'using_chapter',
            'charter_requirement'}:
        return 'REJECT'
    used = {row['value'] for row in SNAPSHOT['domain_labels']}
    if (issue['repository'] != 'SAGE-X-project/sage-spec' or
            issue['registry'] != 'domain_labels' or
            not isinstance(issue['value'], str) or
            re.fullmatch(r'[A-Za-z0-9._|-]{1,128}', issue['value']) is None or
            issue['value'] in used or
            issue['using_chapter'] != 'spec/09-registry.md' or
            re.fullmatch(r'R-[0-9]+', issue['charter_requirement']) is None):
        return 'REJECT'
    changes = proposal.get('pull_request_changes')
    if (not isinstance(changes, list) or
            not {'spec/11-registries.md', issue['using_chapter'],
                 'verification/inspector-plan.md'} <= set(changes) or
            set(proposal.get('inspector_contracts', [])) != {'positive', 'negative'} or
            proposal.get('accepted_order') != len(SNAPSHOT['domain_labels']) + 1):
        return 'REJECT'
    version = proposal.get('wire_version')
    if not isinstance(version, str):
        return 'REJECT'
    match = re.fullmatch(r'0\.([0-9]+)\.([0-9]+)', version)
    if match is None:
        return 'REJECT'
    if proposal.get('incompatible_wire_change') is True:
        if (int(match.group(1)) <= 10 or int(match.group(2)) != 0 or
                not isinstance(proposal.get('migration_notes'), str) or
                not proposal['migration_notes'].strip() or
                'no silent fallback' not in proposal['migration_notes']):
            return 'REJECT'
    return 'ACCEPT'


def check(root=ROOT):
    suite = load((root / SOURCE).read_bytes())
    manifest = load((root / 'verification/0.10.0/current-spec/manifest.json').read_bytes())
    require(suite['schema_version'] == 1 and suite['spec_revision'] == SPEC and
            suite['chapter_sha256'] == CHAPTER_SHA and
            suite['overview_sha256'] == OVERVIEW_SHA and
            manifest['source_sha256']['spec/11-registries.md'] == CHAPTER_SHA and
            manifest['source_sha256']['spec/00-overview.md'] == OVERVIEW_SHA and
            suite['scope'] == 'synthetic registry snapshot and proposal contract; no accepted issue, PR, release, or deployment review' and
            tuple(row['id'] for row in suite['cases']) == IDS and
            suite['document_review_status'] == 'NOT_RUN',
            'pinned TABLE-01 governance source and unobserved review')
    positive = suite['cases'][0]['input']
    require(positive == {'trusted_registry': SNAPSHOT,
                         'candidate_registry': SNAPSHOT,
                         'observed_wire_algorithm': 'ed25519',
                         'wire_scope': 'external'} and
            decision(positive) == 'ACCEPT',
            'unchanged selected registered meanings')
    reused, incompatible, private = [row['input'] for row in suite['cases'][1:]]
    require(reused['candidate_registry']['domain_labels'][1] ==
                {'value': 'sage-pop-v1', 'meaning': 'New Registry key possession',
                 'status': 'assigned'} and
            incompatible['candidate_registry']['signature_algorithms'][0]['digest'] ==
                'SHA-256' and incompatible['candidate_registry']['wire_version'] == '0.10.0' and
            private['observed_wire_algorithm'] == 'x-local-signature' and
            private['wire_scope'] == 'external',
            'retired-value, changed-meaning, and private-wire defects')
    for index, row in enumerate(suite['cases']):
        ident = row['id']
        verdict = 'ACCEPT' if index == 0 else 'REJECT'
        expected = {'verdict': verdict, 'output': {}, 'effects': {}}
        require(decision(row['input']) == verdict and row['expected'] == expected,
                'TABLE-01 case expectation: ' + ident)
        for track in TRACKS:
            relative = 'vectors/0.10.0/current-spec/' + ident + '-' + track + '.json'
            fixture = load((root / relative).read_bytes())
            expected_input = ({'operation': 'sage.registry.value.admit',
                               'input': row['input']} if track == 'runtime' else
                              {'review_subject': 'SAGE-local registry governance',
                               'source': 'spec/11-registries.md',
                               'input': row['input']})
            require(fixture == {'schema_version': 1, 'spec_revision': SPEC,
                                'id': ident, 'track': track,
                                'input': expected_input, 'expected': expected},
                    'TABLE-01 fixture: ' + ident + '/' + track)
    proposal = suite['proposal_control']
    require(proposal_decision(proposal) == 'ACCEPT',
            'synthetic complete registration proposal contract')
    for name, mutate in (
        ('missing-issue', lambda x: x.pop('issue')),
        ('missing-chapter', lambda x: x['pull_request_changes'].remove('spec/09-registry.md')),
        ('missing-negative-test', lambda x: x['inspector_contracts'].remove('negative')),
        ('skipped-order', lambda x: x.update(accepted_order=4)),
        ('silent-version', lambda x: x.update(wire_version='0.10.0')),
        ('no-migration', lambda x: x.update(migration_notes='')),
    ):
        changed = copy.deepcopy(proposal)
        mutate(changed)
        require(proposal_decision(changed) == 'REJECT',
                'registration procedure control: ' + name)
    internal = copy.deepcopy(positive)
    internal['observed_wire_algorithm'] = 'x-local-signature'
    internal['wire_scope'] = 'internal'
    unknown = copy.deepcopy(positive)
    unknown['observed_wire_algorithm'] = 'future-unassigned'
    require(decision(internal) == 'ACCEPT' and decision(unknown) == 'REJECT',
            'private range remains local; public unassigned values fail closed')
    bindings = load((root / 'verification/0.10.0/current-spec/bindings.json').read_bytes())
    require(all(any(binding['id'] == ident and binding['track'] == track and
                    binding['coverage'] == 'partial' and
                    binding['fixture_sha256'] == sha((root / 'vectors/0.10.0/current-spec' /
                                                     (ident + '-' + track + '.json')).read_bytes())
                    for binding in bindings['bindings'])
                for ident in IDS for track in TRACKS),
            'partial runtime and document review bindings')
    return len(IDS), len(TRACKS), 8


if __name__ == '__main__':
    print(check())
