"""Generate bounded security-claim review declarations."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
IDS = ('EXEC-09-P', 'EXEC-09-N01', 'EXEC-09-N02')


def cases():
    return [
        ('EXEC-09-P', {'claim': 'authenticated-execution-intent',
                       'basis': ['valid-signature', 'trusted-authorization-policy',
                                 'enforced-dispatch-boundary'],
                       'scope': 'approved-intent-only'}, 'ACCEPT'),
        ('EXEC-09-N01', {'claim': 'semantic-safety',
                         'basis': ['valid-signature'],
                         'scope': 'all-model-decisions'}, 'REJECT'),
        ('EXEC-09-N02', {'claim': 'whole-host-integrity',
                         'basis': ['file-hash'],
                         'scope': 'entire-host'}, 'REJECT'),
    ]


def main():
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': '0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f',
             'scope': 'synthetic claim declarations only; no review of actual product wording or external attestation',
             'cases': []}
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings'] if row['id'] not in IDS]
    for ident, declaration, verdict in cases():
        expected = {'verdict': verdict, 'output': {}, 'effects': {}}
        suite['cases'].append({'id': ident, 'input': declaration,
                               'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC, 'id': ident,
                   'track': 'document_review',
                   'input': {'review_type': 'security_claim_scope',
                             'declaration': declaration}, 'expected': expected}
        relative = 'vectors/0.10.0/current-spec/' + ident + '.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'document_review',
                                     'fixture': relative,
                                     'fixture_sha256': hashlib.sha256(raw).hexdigest(),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/exec09-claims.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
