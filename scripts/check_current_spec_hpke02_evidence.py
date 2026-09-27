"""Reassess pinned HPKE-02 initiation-binding observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_hpke02_vectors import check as check_vectors, IDS, EXPORTER


BASE = ROOT / 'docs/evidence/current-spec/hpke02'
RUNNER_REVISION = '5117ef63476e542f203bcff14befa53ea22f1edc'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 9, 'UNSUPPORTED': 33,
            'PARTIAL': 19, 'NOT_RUN': 420}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 33,
              'PARTIAL': 26, 'NOT_RUN': 420}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'independent HPKE-02 vector provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'HPKE-02 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 61 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('HPKE-02-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'sixty-one bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'HPKE-02 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'HPKE-02 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(cases['HPKE-02-P']['status'] == 'PARTIAL' and
                all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS[1:])
                and report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'HPKE-02 status promotion: ' + language)
        observation = load((directory / 'HPKE-02-P-runtime.json').read_bytes())
        require(observation['actual'] == {'verdict': 'ACCEPT',
                'output': {'exporter_hex': EXPORTER}, 'effects': {}},
                'HPKE-02 exporter observation: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
