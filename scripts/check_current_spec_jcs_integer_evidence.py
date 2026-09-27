"""Recheck signed JCS-02 core runs and cumulative JCS-01/02 status."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_jcs_integer_vectors import check as check_vectors


BASE = ROOT / 'docs/evidence/current-spec/jcs-integers'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 4, 'UNSUPPORTED': 0,
            'PARTIAL': 8, 'NOT_RUN': 469}),
    'rust': ('SAGE-X-project/rs-sage-core', 'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 0,
              'PARTIAL': 10, 'NOT_RUN': 469}),
}
IDS = sorted([f'JCS-01-N{n:02d}' for n in range(1, 7)] + ['JCS-01-P'] +
             [f'JCS-02-N{n:02d}' for n in range(1, 5)] + ['JCS-02-P'])


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'signed JCS-02 vector provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] ==
                '5c91b718bc0e68ad62aa68da6b01bb391c862451',
                'JCS core/runner identity: ' + language)
        require([row['id'] for row in manifest['observations']] == IDS and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'twelve bounded JCS observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'JCS runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'JCS assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'PARTIAL' for ident in IDS
                    if ident.startswith('JCS-02-')) and
                cases['JCS-01-P']['status'] == 'PARTIAL' and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'JCS status promotion: ' + language)
        outcomes[language] = report['counts']
    return outcomes


if __name__ == '__main__':
    print(check())
