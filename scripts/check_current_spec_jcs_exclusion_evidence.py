"""Reassess the twenty-case JCS run without promoting missing card support."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess
from check_current_spec_jcs_canonical_vectors import check as check_canonical
from check_current_spec_jcs_integer_vectors import check as check_integer
from check_current_spec_jcs_exclusion_vectors import check as check_exclusion


BASE = ROOT / 'docs/evidence/current-spec/jcs-exclusion'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 4, 'UNSUPPORTED': 4,
            'PARTIAL': 12, 'NOT_RUN': 461}),
    'rust': ('SAGE-X-project/rs-sage-core', 'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 4,
              'PARTIAL': 14, 'NOT_RUN': 461}),
}
IDS = sorted([f'JCS-01-N{n:02d}' for n in range(1, 7)] + ['JCS-01-P'] +
             [f'JCS-02-N{n:02d}' for n in range(1, 5)] + ['JCS-02-P'] +
             [f'JCS-03-N{n:02d}' for n in range(1, 4)] + ['JCS-03-P'] +
             [f'JCS-04-N{n:02d}' for n in range(1, 4)] + ['JCS-04-P'])


def check(base=BASE, root=ROOT):
    require(check_integer(root) == 5 and check_canonical(root) == 4 and
            check_exclusion(root) == 4, 'independent JCS vector provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] ==
                '17d2313506bdbb4d1d7af82e6ec3eba433f80105',
                'JCS core/runner identity: ' + language)
        require([row['id'] for row in manifest['observations']] == IDS and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'twenty bounded JCS observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'JCS runner hash: ' + language)
        report = assess(root, directory)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS
                    if ident.startswith('JCS-04-')) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'JCS exclusion status promotion: ' + language)
        outcomes[language] = report['counts']
    return outcomes


if __name__ == '__main__':
    print(check())
