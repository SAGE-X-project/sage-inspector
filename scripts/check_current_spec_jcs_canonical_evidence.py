"""Reassess the preserved sixteen-case JCS-01/02/03 core run."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess
from check_current_spec_jcs_canonical_vectors import check as check_canonical
from check_current_spec_jcs_integer_vectors import check as check_integer


BASE = ROOT / 'docs/evidence/current-spec/jcs-canonical'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 4, 'UNSUPPORTED': 0,
            'PARTIAL': 12, 'NOT_RUN': 465}),
    'rust': ('SAGE-X-project/rs-sage-core', 'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 0,
              'PARTIAL': 14, 'NOT_RUN': 465}),
}
IDS = sorted([f'JCS-01-N{n:02d}' for n in range(1, 7)] + ['JCS-01-P'] +
             [f'JCS-02-N{n:02d}' for n in range(1, 5)] + ['JCS-02-P'] +
             [f'JCS-03-N{n:02d}' for n in range(1, 4)] + ['JCS-03-P'])


def check(base=BASE, root=ROOT):
    require(check_integer(root) == 5 and check_canonical(root) == 4,
            'independent JCS vector provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] ==
                'a899ba8dfc3a195af67274e52584bb42e6ec0f3a',
                'JCS core/runner identity: ' + language)
        require([row['id'] for row in manifest['observations']] == IDS and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'sixteen bounded JCS observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'JCS runner hash: ' + language)
        report = assess(root, directory)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'PARTIAL' for ident in IDS
                    if ident.startswith(('JCS-02-', 'JCS-03-'))) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'JCS status promotion: ' + language)
        outcomes[language] = report['counts']
    return outcomes


if __name__ == '__main__':
    print(check())
