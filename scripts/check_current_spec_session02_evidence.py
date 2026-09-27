"""Reassess pinned SESSION-02 key and lifetime observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_session02_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/session02'
RUNNER_REVISION = 'f3779f3e780ff44bbdd3a9ebe25d7ec862bcb849'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 11, 'UNSUPPORTED': 59,
            'PARTIAL': 25, 'NOT_RUN': 386}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 58,
              'PARTIAL': 32, 'NOT_RUN': 386}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 6, 'independent SESSION-02 vector provenance')
    positive = load((root /
        'vectors/0.10.0/current-spec/SESSION-02-P.json').read_bytes())['expected']
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'SESSION-02 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 95 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'ninety-five bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'SESSION-02 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'SESSION-02 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'PARTIAL' for ident in IDS[:2]) and
                all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS[2:])
                and report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'SESSION-02 status promotion: ' + language)
        opened = load((directory / 'SESSION-02-P-runtime.json').read_bytes())
        require(opened['actual'] == positive,
                'SESSION-02 six core record observations: ' + language)
        denied = load((directory / 'SESSION-02-N01-runtime.json').read_bytes())
        require(denied['actual'] == {'verdict': 'REJECT',
                'output': {}, 'effects': {}},
                'SESSION-02 core sequence cap: ' + language)
        for ident in IDS[2:]:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(observation['actual'] == UNSUPPORTED,
                    'SESSION-02 lifetime support: ' + language + '/' + ident)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
