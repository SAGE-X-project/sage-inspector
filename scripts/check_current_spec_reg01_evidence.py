"""Reassess archived record-validator gaps and isolated key-proof runs."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_reg01_vectors import check as check_vectors, IDS, SOURCE
from run_current_spec_reg01_primitives import inputs as primitive_inputs, NAMES


BASE = ROOT / 'docs/evidence/current-spec/reg01'
RUNNER_REVISION = '42ddbf5f5e98c55830b546ae5c68ea7acc6d759e'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 139,
            'PARTIAL': 33, 'NOT_RUN': 291}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 138,
              'PARTIAL': 40, 'NOT_RUN': 291}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == (5, 3),
            'independent REG-01 record fixture provenance')
    outcomes = {}
    for language, (repository, revision, executable_sha, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] ==
                    '5bcf511e604579afa63f434013447f44b6858828',
                'REG-01 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 190 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred ninety bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'REG-01 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'REG-01 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'REG-01 unavailable complete record verifier: ' +
                    language + '/' + ident)
        outcomes[language] = counts
    primitives = load((base / 'primitives/report.json').read_bytes())
    require(primitives['schema_version'] == 1 and
            primitives['spec_revision'] ==
                '5bcf511e604579afa63f434013447f44b6858828' and
            primitives['runner_revision'] == RUNNER_REVISION and
            primitives['scenario_sha256'] == sha((root / SOURCE).read_bytes()) and
            primitives['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_reg01_primitives.py').read_bytes()) and
            primitives['bridge_sha256'] ==
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) and
            primitives['inputs'] == primitive_inputs(root),
            'REG-01 proof primitive provenance')
    for language, (repository, revision, executable_sha, _) in REVISIONS.items():
        require(primitives['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha},
                'REG-01 primitive subject identity: ' + language)
        observations = primitives['observations'][language]
        require(tuple(observations) == NAMES,
                'five selected proof observations: ' + language)
        for name, row in observations.items():
            require(row == {
                'schema_version': 1,
                'case_id': 'REG-01-' + name,
                'verdict': 'ACCEPT', 'output': {'valid': True},
            }, 'valid isolated proof does not establish record acceptance: '
                + language + '/' + name)
    return outcomes


if __name__ == '__main__':
    print(check())
