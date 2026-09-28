"""Reassess CARD-02 full-verifier gaps and bounded signature primitives."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_card02_vectors import check as check_vectors, IDS
from run_current_spec_card02_primitives import inputs as primitive_inputs


BASE = ROOT / 'docs/evidence/current-spec/card02'
RUNNER_REVISION = 'aeb0d5fae4cc41d84b73e09dd93d70c7d08f490b'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 98,
            'PARTIAL': 33, 'NOT_RUN': 332}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 97,
              'PARTIAL': 40, 'NOT_RUN': 332}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}
PRIMITIVE_IDS = ('valid', 'legacy-proof', 'altered-method', 'wrong-domain')


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'independent CARD-02 fixture provenance')
    outcomes = {}
    for language, (repository, revision, executable_sha, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'CARD-02 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 149 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred forty-nine bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'CARD-02 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'CARD-02 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'CARD-02 unsupported card verifier: ' + language + '/' + ident)
        outcomes[language] = counts
    primitives = load((base / 'primitives/report.json').read_bytes())
    source = root / 'vectors/0.10.0/registry-records.json'
    require(primitives['schema_version'] == 1 and
            primitives['runner_revision'] == RUNNER_REVISION and
            primitives['source_sha256'] == sha(source.read_bytes()) and
            primitives['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_card02_primitives.py').read_bytes()) and
            primitives['bridge_sha256'] ==
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) and
            primitives['inputs'] == primitive_inputs(root),
            'CARD-02 signature primitive provenance')
    for language, (repository, revision, executable_sha, _) in REVISIONS.items():
        require(primitives['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha},
                'CARD-02 primitive executable identity: ' + language)
        actual = primitives['observations'][language]
        require(tuple(actual) == PRIMITIVE_IDS,
                'CARD-02 primitive case identity: ' + language)
        for ident in PRIMITIVE_IDS:
            expected = {'schema_version': 1,
                        'case_id': 'CARD-02-' + ident,
                        'verdict': 'REJECT' if ident == 'wrong-domain' else 'ACCEPT',
                        'output': {} if ident == 'wrong-domain' else {'valid': True}}
            require(actual[ident] == expected,
                    'CARD-02 bounded signature primitive: ' + language + '/' + ident)
    return outcomes


if __name__ == '__main__':
    print(check())
