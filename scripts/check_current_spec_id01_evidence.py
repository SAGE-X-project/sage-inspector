"""Reassess pinned ID-01 DID grammar observations without false promotions."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_id01_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/id01'
RUNNER_REVISION = 'c53940c59541db6a0907654282946b279c3e4fee'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 16, 'UNSUPPORTED': 75,
            'PARTIAL': 33, 'NOT_RUN': 357}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 10, 'UNSUPPORTED': 74,
              'PARTIAL': 40, 'NOT_RUN': 357}),
}
ACTUAL = {
    'ID-01-P': {'verdict': 'REJECT', 'output': {}, 'effects': {}},
    'ID-01-N01': {'verdict': 'ACCEPT', 'output': {
        'control_verdict': 'REJECT', 'candidate_verdict': 'ACCEPT'}, 'effects': {}},
    **{ident: {'verdict': 'ACCEPT', 'output': {
        'control_verdict': 'REJECT', 'candidate_verdict': 'REJECT'}, 'effects': {}}
       for ident in ('ID-01-N02', 'ID-01-N03', 'ID-01-N04')},
    'ID-01-N05': {'verdict': 'UNSUPPORTED',
                  'reason': 'Core primitive adapter does not expose this operation.'},
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 6, 'independent ID-01 fixture provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'ID-01 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 124 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred twenty-four bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'ID-01 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'ID-01 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'FAIL' for ident in IDS[:-1]) and
                cases['ID-01-N05']['status'] == 'UNSUPPORTED',
                'ID-01 false syntax promotion: ' + language)
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(observation['actual'] == ACTUAL[ident],
                    'ID-01 core DID result: ' + language + '/' + ident)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
