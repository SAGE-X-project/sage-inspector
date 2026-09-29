"""Reassess pinned ID-02 identity and normalization observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_id02_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/id02'
RUNNER_REVISION = '7d560bde61e4750e687a10b2d295a0d3a8760dc9'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 77,
            'PARTIAL': 33, 'NOT_RUN': 353}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 76,
              'PARTIAL': 40, 'NOT_RUN': 353}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}
ACTUAL = {
    'ID-02-P': UNSUPPORTED,
    'ID-02-N01': UNSUPPORTED,
    'ID-02-N02': {'verdict': 'ACCEPT', 'output': {
        'control_verdict': 'REJECT', 'candidate_verdict': 'ACCEPT'}, 'effects': {}},
    'ID-02-N03': {'verdict': 'ACCEPT', 'output': {
        'control_verdict': 'REJECT', 'candidate_verdict': 'REJECT'}, 'effects': {}},
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 4, 'independent ID-02 fixture provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'ID-02 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 128 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred twenty-eight bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'ID-02 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'ID-02 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'UNSUPPORTED'
                    for ident in IDS[:2]) and
                all(cases[ident]['status'] == 'FAIL' for ident in IDS[2:]),
                'ID-02 authority and syntax status: ' + language)
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(observation['actual'] == ACTUAL[ident],
                    'ID-02 core identity result: ' + language + '/' + ident)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
