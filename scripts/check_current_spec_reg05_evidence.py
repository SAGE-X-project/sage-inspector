"""Reassess archived Registry observation results and bounded core gates."""

import json

from check_current_spec_reg05_vectors import check as check_vectors, IDS, CONTROLS, SOURCE, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/reg05'
RUNNER_REVISION = 'd3f2268098688e00628d79e8b6c4e6f6e7ec4326'
REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           'f655775a1ea7879219d115cd2d346d70dce9977929456f4450b32586dd9f8c80',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 159,
            'PARTIAL': 33, 'NOT_RUN': 271}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             '9e51172c562a2942b1b4376aa193fa8b84408b3a8c77860b56f56f8733cb31cb',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 158,
              'PARTIAL': 40, 'NOT_RUN': 271}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}
SCOPE = ('synthetic trusted source, injected clock, and local journal; '
         'no deployed finality proof')


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == (6, 3),
            'independent REG-05 observation fixture provenance')
    outcomes = {}
    for language, (repository, revision, executable_sha, _, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC,
                'REG-05 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 210 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'two hundred ten bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'REG-05 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'REG-05 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'REG-05 unavailable complete observation boundary: ' +
                    language + '/' + ident)
        outcomes[language] = counts

    gate = load((base / 'gate/report.json').read_bytes())
    suite = load((root / SOURCE).read_bytes())
    require(gate['schema_version'] == 1 and gate['spec_revision'] == SPEC and
            gate['scenario_sha256'] == sha((root / SOURCE).read_bytes()) and
            gate['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_reg05_gate.py').read_bytes()) and
            gate['runner_revision'] == RUNNER_REVISION and
            gate['scope'] == SCOPE and
            set(gate['subjects']) == set(REVISIONS) and
            set(gate['observations']) == set(REVISIONS),
            'REG-05 bounded gate provenance and scope')
    rows = suite['cases'] + suite['supplemental']
    require(tuple(row['id'] for row in rows) == IDS + CONTROLS,
            'REG-05 selected scenarios and controls')
    for language, (repository, revision, _, gate_sha, _) in REVISIONS.items():
        require(gate['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': gate_sha},
                'REG-05 bounded gate subject: ' + language)
        observations = gate['observations'][language]
        require(tuple(observations) == IDS + CONTROLS,
                'REG-05 bounded gate inventory: ' + language)
        for row in rows:
            requests = [{'id': str(index), 'request': step['request']}
                        for index, step in enumerate(row['scenario']['steps'])]
            wire = ''.join(json.dumps(request, separators=(',', ':')) + '\n'
                           for request in requests).encode()
            expected = [{'id': str(index), **step['expected']}
                        for index, step in enumerate(row['scenario']['steps'])]
            actual = observations[row['id']]
            require(actual == {
                        'source_scenario': row['source_scenario'],
                        'focus_step': row['focus_step'],
                        'input_sha256': sha(wire), 'actual_steps': expected,
                        'focus_actual': expected[row['focus_step']]},
                    'REG-05 bounded gate result: ' + language + '/' + row['id'])
    return outcomes


if __name__ == '__main__':
    print(check())
