"""Reassess MSG-03 observations without promoting response acceptance."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_msg03_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/msg03'
RUNNER_REVISION = '2ab14c10bff2cd07cfbc3f6a8e3573c2df45b055'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 7, 'UNSUPPORTED': 12,
            'PARTIAL': 17, 'NOT_RUN': 445}, 'FAIL'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 12,
              'PARTIAL': 22, 'NOT_RUN': 445}, 'PARTIAL'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'independent MSG-03 vector provenance')
    outcomes = {}
    for language, (repository, revision, counts, positive_status) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'MSG-03 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 36 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('MSG-03-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'thirty-six bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'MSG-03 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'MSG-03 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(cases['MSG-03-P']['status'] == positive_status and
                all(cases[ident]['status'] == 'PARTIAL' for ident in
                    ('MSG-03-N02', 'MSG-03-N04')) and
                all(cases[ident]['status'] == 'UNSUPPORTED' for ident in
                    ('MSG-03-N01', 'MSG-03-N03')) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'MSG-03 status promotion: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
