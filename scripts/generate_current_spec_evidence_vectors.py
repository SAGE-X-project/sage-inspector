"""Bind EVIDENCE-01 across runtime, document and deployment review."""

import json
from pathlib import Path

from current_spec_catalog import sha
from current_spec_evidence_review import IDS, TRACKS, evaluate


ROOT = Path(__file__).resolve().parents[1]
SPEC = '5bcf511e604579afa63f434013447f44b6858828'


def scenarios():
    positive = {'claim': 'measured_interoperability', 'spec_revision': SPEC,
                'executions': [{'input_sha256': '1' * 64,
                                'revision': '2' * 40, 'duration_ms': 7}],
                'implementations': [
                    {'repository': 'example/go', 'revision': '2' * 40,
                     'executable_sha256': '3' * 64},
                    {'repository': 'example/rust', 'revision': '4' * 40,
                     'executable_sha256': '5' * 64}]}
    missing = dict(positive, executions=[])
    duplicate = dict(positive, implementations=[positive['implementations'][0],
                                                 dict(positive['implementations'][1],
                                                      executable_sha256='3' * 64)])
    return dict(zip(IDS, (positive, missing, duplicate)))


def cases():
    scenarios_by_id = scenarios()
    for ident in IDS:
        for track in TRACKS:
            report = scenarios_by_id[ident]
            yield ident, track, {'operation': 'sage.evidence.review',
                                 'report': report}, evaluate(ident, track, report)


def main():
    binding_path = ROOT / 'verification/0.10.0/current-spec/bindings.json'
    bindings = json.loads(binding_path.read_text())
    bindings['bindings'] = [row for row in bindings['bindings']
                            if row['id'] not in IDS]
    source = ROOT / 'verification/0.10.0/current-spec/sources/charter.md'
    suite = {'schema_version': 1, 'spec_revision': SPEC,
             'source_sha256': sha(source.read_bytes()),
             'scope': 'synthetic report admission; implementation performance and interoperability remain unmeasured',
             'cases': []}
    for ident, track, inp, expected in cases():
        suite['cases'].append({'id': ident, 'track': track,
                               'input': inp, 'expected': expected})
        fixture = {'schema_version': 1, 'spec_revision': SPEC,
                   'id': ident, 'track': track,
                   'input': inp, 'expected': expected}
        relative = f'vectors/0.10.0/current-spec/{ident}-{track}.json'
        raw = (json.dumps(fixture, indent=2) + '\n').encode()
        (ROOT / relative).write_bytes(raw)
        bindings['bindings'].append({'id': ident, 'track': track,
                                     'fixture': relative, 'fixture_sha256': sha(raw),
                                     'coverage': 'partial'})
    (ROOT / 'vectors/0.10.0/evidence-review.json').write_text(
        json.dumps(suite, indent=2) + '\n')
    binding_path.write_text(json.dumps(bindings, indent=2) + '\n')


if __name__ == '__main__':
    main()
