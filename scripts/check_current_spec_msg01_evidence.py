"""Reassess preserved MSG-01 core observations without promoting profile support."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_msg01_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/msg01'
RUNNER_REVISION = '5ab5403f065d21eab87fe73e3ee332fdc5a3b557'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 7,
            'PARTIAL': 13, 'NOT_RUN': 456}, 'FAIL'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 7,
              'PARTIAL': 16, 'NOT_RUN': 456}, 'PARTIAL'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'independent MSG-01 vector provenance')
    outcomes = {}
    for language, (repository, revision, counts, positive_status) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'MSG-01 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 25 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('MSG-01-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'twenty-five bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'MSG-01 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'MSG-01 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(cases['MSG-01-P']['status'] == positive_status and
                cases['MSG-01-N04']['status'] == 'PARTIAL' and
                all(cases[ident]['status'] == 'UNSUPPORTED' for ident in
                    ('MSG-01-N01', 'MSG-01-N02', 'MSG-01-N03')) and
                all(cases[ident]['status'] == 'UNSUPPORTED' for ident in
                    ('JCS-04-P', 'JCS-04-N01', 'JCS-04-N02', 'JCS-04-N03')) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'MSG-01 status promotion: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
