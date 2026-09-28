"""Reassess whole-request signature gaps and bounded core primitives."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_transport02_vectors import check as check_vectors, IDS
from run_current_spec_transport02_primitives import inputs as primitive_inputs


BASE = ROOT / 'docs/evidence/current-spec/transport02'
RUNNER_REVISION = '65cacb475326e251fe69b84fe5bde6f6a46cc1fe'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 113,
            'PARTIAL': 33, 'NOT_RUN': 317}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 112,
              'PARTIAL': 40, 'NOT_RUN': 317}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'independent TRANSPORT-02 fixture provenance')
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
                'TRANSPORT-02 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 164 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred sixty-four bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'TRANSPORT-02 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'TRANSPORT-02 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'TRANSPORT-02 unavailable request verifier: ' +
                    language + '/' + ident)
        outcomes[language] = counts
    primitives = load((base / 'primitives/report.json').read_bytes())
    source = root / 'vectors/0.10.0/http-boundaries.json'
    require(primitives['schema_version'] == 1 and
            primitives['runner_revision'] == RUNNER_REVISION and
            primitives['source_sha256'] == sha(source.read_bytes()) and
            primitives['fixture_sha256'] == {
                ident: sha((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes()) for ident in IDS} and
            primitives['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_transport02_primitives.py').read_bytes()) and
            primitives['bridge_sha256'] ==
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) and
            primitives['inputs'] == primitive_inputs(root),
            'TRANSPORT-02 signature primitive provenance')
    for language, (repository, revision, executable_sha, _) in REVISIONS.items():
        require(primitives['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha},
                'TRANSPORT-02 primitive subject identity: ' + language)
        actual = primitives['observations'][language]
        require(tuple(actual) == IDS, 'TRANSPORT-02 primitive IDs: ' + language)
        for ident in IDS:
            accept = ident in ('TRANSPORT-02-P', 'TRANSPORT-02-N04')
            require(actual[ident] == {
                        'schema_version': 1, 'case_id': ident,
                        'verdict': 'ACCEPT' if accept else 'REJECT',
                        'output': {'valid': True} if accept else {}},
                    'TRANSPORT-02 generic signature observation: ' +
                    language + '/' + ident)
    return outcomes


if __name__ == '__main__':
    print(check())
