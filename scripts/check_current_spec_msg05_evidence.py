"""Reassess pinned MSG-05 observations without promoting journal evidence."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_msg05_vectors import check as check_vectors, IDS
from check_core_lifecycle_evidence import check as check_journal


BASE = ROOT / 'docs/evidence/current-spec/msg05'
RUNNER_REVISION = '3d7bd9a48b248e50e4223de87f98da5b96e184bc'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 8, 'UNSUPPORTED': 23,
            'PARTIAL': 17, 'NOT_RUN': 433}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 23,
              'PARTIAL': 23, 'NOT_RUN': 433}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 6, 'independent MSG-05 scenario provenance')
    journal = check_journal()
    require(journal['conformance'] == 'NOT_ESTABLISHED',
            'journal evidence was promoted to conformance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'MSG-05 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 48 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('MSG-05-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'forty-eight bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'MSG-05 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'MSG-05 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS)
                and report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'MSG-05 status promotion: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
