"""Reassess pinned SESSION-03 record and AAD observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_session03_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/session03'
RUNNER_REVISION = '6e1fa7c5f71d073e55249c629c4e25b0b2d04678'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 11, 'UNSUPPORTED': 59,
            'PARTIAL': 33, 'NOT_RUN': 378}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 58,
              'PARTIAL': 40, 'NOT_RUN': 378}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 8, 'independent SESSION-03 fixture provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'SESSION-03 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 103 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred three bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'SESSION-03 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'SESSION-03 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'PARTIAL' for ident in IDS) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'SESSION-03 status promotion: ' + language)
        for ident in IDS:
            expected = load((root / 'vectors/0.10.0/current-spec' /
                             (ident + '.json')).read_bytes())['expected']
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(observation['actual'] == expected,
                    'SESSION-03 core record result: ' + language + '/' + ident)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
