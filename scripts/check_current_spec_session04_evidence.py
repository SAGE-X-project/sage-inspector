"""Reassess pinned SESSION-04 stateful-operation support observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_session04_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/session04'
RUNNER_REVISION = '7bce1fd7a771f13bb56360e8716cd072efd4b141'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 11, 'UNSUPPORTED': 63,
            'PARTIAL': 33, 'NOT_RUN': 374}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 62,
              'PARTIAL': 40, 'NOT_RUN': 374}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 4, 'independent SESSION-04 fixture provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'SESSION-04 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 107 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred seven bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'SESSION-04 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'SESSION-04 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'SESSION-04 false stateful promotion: ' + language)
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(observation['actual'] == {
                'verdict': 'UNSUPPORTED',
                'reason': 'Core primitive adapter does not expose this operation.'},
                'SESSION-04 missing stateful operation: ' + language + '/' + ident)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
