"""Reassess pinned HPKE-04 completion signature observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_hpke04_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/hpke04'
RUNNER_REVISION = 'aaf68cac65f07a385e301d057edf8a9de7ba49a8'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 11, 'UNSUPPORTED': 39,
            'PARTIAL': 21, 'NOT_RUN': 410}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 38,
              'PARTIAL': 28, 'NOT_RUN': 410}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'independent HPKE-04 vector provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'HPKE-04 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 71 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('HPKE-04-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'seventy-one bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'HPKE-04 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'HPKE-04 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'PARTIAL' for
                    ident in ('HPKE-04-P', 'HPKE-04-N04')) and
                all(cases[ident]['status'] == 'UNSUPPORTED' for
                    ident in IDS[1:4]) and report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'HPKE-04 status promotion: ' + language)
        require(load((directory / 'HPKE-04-P-runtime.json').read_bytes())
                    ['actual'] == {'verdict': 'ACCEPT',
                                  'output': {'valid': True}, 'effects': {}} and
                load((directory / 'HPKE-04-N04-runtime.json').read_bytes())
                    ['actual'] == {'verdict': 'REJECT',
                                  'output': {}, 'effects': {}},
                'HPKE-04 inner signature observations: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
