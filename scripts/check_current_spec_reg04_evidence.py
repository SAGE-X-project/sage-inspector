"""Reassess archived Registry proof and endorsement observations."""

from check_current_spec_reg04_vectors import check as check_vectors, IDS, SOURCE
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from run_current_spec_reg04_primitives import inputs as primitive_inputs, NAMES


BASE = ROOT / 'docs/evidence/current-spec/reg04'
RUNNER_REVISION = 'f1623637b0e9776846268ccbbd6ad5b47ff3f4f8'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 153,
            'PARTIAL': 33, 'NOT_RUN': 277}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 152,
              'PARTIAL': 40, 'NOT_RUN': 277}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == (5, 4),
            'independent REG-04 proof fixture provenance')
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
                'REG-04 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 204 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'two hundred four bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'REG-04 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'REG-04 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'REG-04 unavailable complete proof boundary: ' +
                    language + '/' + ident)
        outcomes[language] = counts
    primitives = load((base / 'primitives/report.json').read_bytes())
    require(primitives['schema_version'] == 1 and
            primitives['spec_revision'] ==
                '5bcf511e604579afa63f434013447f44b6858828' and
            primitives['runner_revision'] == RUNNER_REVISION and
            primitives['scenario_sha256'] == sha((root / SOURCE).read_bytes()) and
            primitives['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_reg04_primitives.py').read_bytes()) and
            primitives['bridge_sha256'] ==
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) and
            primitives['inputs'] == primitive_inputs(root),
            'REG-04 proof primitive provenance')
    expected = {name: ('REJECT' if name == 'wrong-registry' else 'ACCEPT')
                for name in NAMES}
    for language, (repository, revision, executable_sha, _) in REVISIONS.items():
        require(primitives['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha},
                'REG-04 primitive subject identity: ' + language)
        observations = primitives['observations'][language]
        require(tuple(observations) == NAMES,
                'six selected proof observations: ' + language)
        for name, verdict in expected.items():
            require(observations[name] == {
                'schema_version': 1, 'case_id': 'REG-04-' + name,
                'verdict': verdict,
                'output': {'valid': True} if verdict == 'ACCEPT' else {},
            }, 'isolated Ed25519 proof does not grant Registry authority: ' +
                    language + '/' + name)
    return outcomes


if __name__ == '__main__':
    print(check())
