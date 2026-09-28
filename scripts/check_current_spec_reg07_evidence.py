"""Reassess reserved-profile observations and isolated legacy DID parsing."""

import json

from check_current_spec_reg07_vectors import check as check_vectors, IDS, SOURCE, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/reg07'
RUNNER_REVISION = 'a5de8984ec52dc3986f59624d0592f5a0c012198'
REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 166,
            'PARTIAL': 33, 'NOT_RUN': 264}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 165,
              'PARTIAL': 40, 'NOT_RUN': 264}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}
SCOPE = 'legacy DID syntax primitive only; no Registry resolver or profile admission'


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == (2, 3), 'independent REG-07 fixture provenance')
    outcomes = {}
    for language, (repository, revision, executable_sha, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC,
                'REG-07 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 217 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'two hundred seventeen bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'REG-07 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'REG-07 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'REG-07 unavailable complete resolver boundary: ' +
                    language + '/' + ident)
        outcomes[language] = counts
    primitives = load((base / 'primitives/report.json').read_bytes())
    suite = load((root / SOURCE).read_bytes())
    require(primitives['schema_version'] == 1 and
            primitives['spec_revision'] == SPEC and
            primitives['scenario_sha256'] == sha((root / SOURCE).read_bytes()) and
            primitives['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_reg07_primitives.py').read_bytes()) and
            primitives['runner_revision'] == RUNNER_REVISION and
            primitives['scope'] == SCOPE and
            set(primitives['subjects']) == set(REVISIONS) and
            set(primitives['observations']) == set(REVISIONS),
            'REG-07 primitive scope and provenance')
    for language, (repository, revision, executable_sha, _) in REVISIONS.items():
        require(primitives['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha},
                'REG-07 primitive subject: ' + language)
        observations = primitives['observations'][language]
        require(tuple(observations) == ('reserved', 'web', 'eip155'),
                'REG-07 primitive control order: ' + language)
        for row in suite['primitive_controls']:
            ident = row['id']
            request = {'schema_version': 1, 'protocol_version': '0.10.0',
                       'profile': 'primitive-foundation',
                       'case_id': 'REG-07-' + ident,
                       'operation': 'sage.did.validate',
                       'input': {'did': row['did']}}
            raw = json.dumps(request, sort_keys=True,
                             separators=(',', ':')).encode()
            verdict = 'ACCEPT' if ident == 'reserved' else 'REJECT'
            expected = {'case_id': request['case_id'],
                        'output': {'valid': True} if verdict == 'ACCEPT' else {},
                        'schema_version': 1, 'verdict': verdict}
            require(observations[ident] == {
                        'input_sha256': sha(raw), 'actual': expected},
                    'REG-07 isolated legacy parser observation: ' +
                    language + '/' + ident)
    return outcomes


if __name__ == '__main__':
    print(check())
