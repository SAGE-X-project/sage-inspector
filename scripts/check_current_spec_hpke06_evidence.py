"""Reassess pinned HPKE-06 handshake admission observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_hpke06_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/hpke06'
RUNNER_REVISION = 'a53ab6dd373816920ec7296e6086dfd3b5b218d4'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 11, 'UNSUPPORTED': 48,
            'PARTIAL': 22, 'NOT_RUN': 400}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 47,
              'PARTIAL': 29, 'NOT_RUN': 400}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'independent HPKE-06 vector provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'HPKE-06 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 81 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('HPKE-06-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'eighty-one bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'HPKE-06 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'HPKE-06 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'HPKE-06 status promotion: ' + language)
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(observation['actual'] == UNSUPPORTED,
                    'HPKE-06 primitive support: ' + language + '/' + ident)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
