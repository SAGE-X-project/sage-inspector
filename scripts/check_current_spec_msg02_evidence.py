"""Reassess MSG-02 observations without promoting unavailable HTTP checks."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_msg02_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/msg02'
RUNNER_REVISION = '84303420690459ccb696ab9aab30b1ffcfe83906'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 6, 'UNSUPPORTED': 10,
            'PARTIAL': 15, 'NOT_RUN': 450}, 'FAIL'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 10,
              'PARTIAL': 19, 'NOT_RUN': 450}, 'PARTIAL'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 6, 'independent MSG-02 vector provenance')
    outcomes = {}
    for language, (repository, revision, counts, positive_status) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'MSG-02 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 31 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('MSG-02-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'thirty-one bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'MSG-02 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'MSG-02 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(cases['MSG-02-P']['status'] == positive_status and
                all(cases[ident]['status'] == 'PARTIAL' for ident in
                    ('MSG-02-N03', 'MSG-02-N04')) and
                all(cases[ident]['status'] == 'UNSUPPORTED' for ident in
                    ('MSG-02-N01', 'MSG-02-N02', 'MSG-02-N05')) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'MSG-02 status promotion: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
