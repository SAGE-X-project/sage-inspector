"""Generate bounded SAGE-local registry governance review fixtures."""

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('TABLE-01-P', 'TABLE-01-N01', 'TABLE-01-N02', 'TABLE-01-N03')
TRACKS = ('runtime', 'document_review')


def registry_snapshot():
    return {
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


def main():
    trusted = registry_snapshot()
    good = {'trusted_registry': trusted,
            'candidate_registry': copy.deepcopy(trusted),
            'observed_wire_algorithm': 'ed25519',
            'wire_scope': 'external'}
    reused = copy.deepcopy(good)
    reused['candidate_registry']['domain_labels'][1].update(
        meaning='New Registry key possession', status='assigned')
    incompatible = copy.deepcopy(good)
    incompatible['candidate_registry']['signature_algorithms'][0]['digest'] = 'SHA-256'
    private = copy.deepcopy(good)
    private['observed_wire_algorithm'] = 'x-local-signature'
    rows = [
        ('TABLE-01-P', good, 'ACCEPT', 'registered meanings and version unchanged'),
        ('TABLE-01-N01', reused, 'REJECT', 'obsolete domain label reused'),
        ('TABLE-01-N02', incompatible, 'REJECT', 'silent incompatible algorithm meaning'),
        ('TABLE-01-N03', private, 'REJECT', 'private signature value on external wire'),
    ]
    cases = []
    for ident, inp, verdict, purpose in rows:
        expected = {'verdict': verdict, 'output': {}, 'effects': {}}
        cases.append({'id': ident, 'purpose': purpose, 'input': inp,
                      'expected': expected})
        for track in TRACKS:
            fixture = {'schema_version': 1, 'spec_revision': SPEC,
                       'id': ident, 'track': track,
                       'input': ({'operation': 'sage.registry.value.admit',
                                  'input': inp} if track == 'runtime' else
                                 {'review_subject': 'SAGE-local registry governance',
                                  'source': 'spec/11-registries.md',
                                  'input': inp}),
                       'expected': expected}
            relative = 'vectors/0.10.0/current-spec/' + ident + '-' + track + '.json'
            (ROOT / relative).write_text(json.dumps(fixture, indent=2) + '\n')
    proposal = {
        'issue': {'repository': 'SAGE-X-project/sage-spec',
                  'registry': 'domain_labels', 'value': 'sage-example-0.11.0',
                  'using_chapter': 'spec/09-registry.md',
                  'charter_requirement': 'R-34'},
        'pull_request_changes': ['spec/11-registries.md', 'spec/09-registry.md',
                                 'verification/inspector-plan.md'],
        'inspector_contracts': ['positive', 'negative'],
        'accepted_order': 3,
        'wire_version': '0.11.0',
        'incompatible_wire_change': True,
        'migration_notes': 'Explicit version transition; no silent fallback',
    }
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'chapter_sha256': 'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
             'overview_sha256': '82493ba53f38cc783a2e76ffab3a70dc069b6ac3e534c7422840369fc90d9978',
             'scope': 'synthetic registry snapshot and proposal contract; no accepted issue, PR, release, or deployment review',
             'cases': cases, 'proposal_control': proposal,
             'document_review_status': 'NOT_RUN'}
    (ROOT / 'vectors/0.10.0/table01-scenarios.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident in IDS:
        for track in TRACKS:
            relative = 'vectors/0.10.0/current-spec/' + ident + '-' + track + '.json'
            bindings['bindings'].append({
                'id': ident, 'track': track, 'fixture': relative,
                'fixture_sha256': hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                'coverage': 'partial'})
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
