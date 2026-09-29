"""Reassess archived HTTP receive gaps and isolated signature observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_transport05_vectors import check as check_vectors, IDS, SOURCE
from run_current_spec_transport05_primitives import inputs as primitive_inputs, VARIANTS


BASE = ROOT / 'docs/evidence/current-spec/transport05'
RUNNER_REVISION = 'e17e82226f9e59c4142ab484e22bd78533bc42aa'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 129,
            'PARTIAL': 33, 'NOT_RUN': 301}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 128,
              'PARTIAL': 40, 'NOT_RUN': 301}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 9, 'independent TRANSPORT-05 fixture provenance')
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
                'TRANSPORT-05 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 180 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred eighty bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'TRANSPORT-05 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'TRANSPORT-05 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'TRANSPORT-05 unavailable joint HTTP receiver: ' +
                    language + '/' + ident)
        outcomes[language] = counts
    primitives = load((base / 'primitives/report.json').read_bytes())
    require(primitives['schema_version'] == 1 and
            primitives['spec_revision'] ==
                '5bcf511e604579afa63f434013447f44b6858828' and
            primitives['runner_revision'] == RUNNER_REVISION and
            primitives['scenario_sha256'] == sha((root / SOURCE).read_bytes()) and
            primitives['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_transport05_primitives.py').read_bytes()) and
            primitives['bridge_sha256'] ==
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) and
            primitives['inputs'] == primitive_inputs(root),
            'TRANSPORT-05 signature primitive provenance')
    for language, (repository, revision, executable_sha, _) in REVISIONS.items():
        require(primitives['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha},
                'TRANSPORT-05 primitive subject identity: ' + language)
        actual = primitives['observations'][language]
        require(tuple(actual) == VARIANTS and
                sum(len(parts) for parts in actual.values()) == 16,
                'sixteen signature observations: ' + language)
        for name, parts in actual.items():
            require(set(parts) == set(primitives['inputs'][name]),
                    'present signatures only: ' + language + '/' + name)
            for side, row in parts.items():
                require(row == {'schema_version': 1,
                                'case_id': name + '-' + side,
                                'verdict': 'ACCEPT',
                                'output': {'valid': True}},
                        'generic signature observation: ' +
                        language + '/' + name + '/' + side)
    return outcomes


if __name__ == '__main__':
    print(check())
