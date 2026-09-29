"""Bind nine process review cases to pinned source and provenance decisions."""

import hashlib
import json
from pathlib import Path

from current_spec_process_review import IDS, evaluate


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'
HISTORICAL = 'f4a4e7fbf71a665785984eef7609b2e8fabe833d'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def configurations():
    normative = {'source_of_truth': 'normative_text',
                 'remove_case_mapping': False}
    evidence = {'vector_revision': HISTORICAL,
                'observation_present': True, 'claimed_status': 'PASS'}
    repositories = {'canonical_sources': ['spec/', 'profiles/', 'charter.md'],
                    'touched_repositories': ['sage-inspector', 'sage-spec']}
    return {
        'PROC-01-P': normative,
        'PROC-01-N01': dict(normative, remove_case_mapping=True),
        'PROC-01-N02': dict(normative, source_of_truth='implementation'),
        'PROC-02-P': evidence,
        'PROC-02-N01': dict(evidence, vector_revision=SPEC),
        'PROC-02-N02': dict(evidence, observation_present=False),
        'PROC-03-P': repositories,
        'PROC-03-N01': dict(repositories, canonical_sources=
                            repositories['canonical_sources'] + ['docs/new-spec.md']),
        'PROC-03-N02': dict(repositories, touched_repositories=
                            repositories['touched_repositories'] + ['sage']),
    }


def cases():
    trace = json.loads((ROOT / 'verification/0.10.0/current-spec/traceability.json').read_text())
    for ident in IDS:
        config = configurations()[ident]
        yield ident, {'operation': 'sage.process.review',
                      'input': {'configuration': config}}, \
            evaluate(ident, config, trace, HISTORICAL, SPEC)


def main():
    path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'process_sha256': sha((ROOT / 'verification/0.10.0/current-spec/sources/PROCESS.md').read_bytes()),
             'historical_revision': HISTORICAL,
             'scope': 'pinned process-source and in-memory negative review controls; product repositories are not executed or modified',
             'cases': []}
    for ident, inp, expected in cases():
        suite['cases'].append({'id': ident, 'input': inp,
                               'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': 'document_review',
                   'input': inp, 'expected': expected}
        relative = f'vectors/0.10.0/current-spec/{ident}-document_review.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': 'document_review',
                                     'fixture': relative,
                                     'fixture_sha256': sha(raw),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/process-review.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
