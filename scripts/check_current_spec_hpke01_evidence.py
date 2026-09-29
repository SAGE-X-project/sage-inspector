"""Reassess pinned HPKE-01 exporter and establishment observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_hpke01_vectors import check as check_vectors, IDS, EXPORTER


BASE = ROOT / 'docs/evidence/current-spec/hpke01'
RUNNER_REVISION = 'fdbf6d163d14b8757d6d526e81d0f31c23aa4e94'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 9, 'UNSUPPORTED': 29,
            'PARTIAL': 18, 'NOT_RUN': 425}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 29,
              'PARTIAL': 25, 'NOT_RUN': 425}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 4, 'independent HPKE-01 vector provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'HPKE-01 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 56 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('HPKE-01-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'fifty-six bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'HPKE-01 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'HPKE-01 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(cases['HPKE-01-P']['status'] == 'PARTIAL' and
                all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS[1:])
                and report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'HPKE-01 status promotion: ' + language)
        observation = load((directory / 'HPKE-01-P-runtime.json').read_bytes())
        require(observation['actual'] == {'verdict': 'ACCEPT',
                'output': {'exporter_hex': EXPORTER}, 'effects': {}},
                'HPKE-01 RFC exporter observation: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
