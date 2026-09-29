"""Reassess pinned SESSION-01 identity and tuple observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_session01_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/session01'
RUNNER_REVISION = '0fe942b3be014b4583a303173f0cf59a8006d212'
SID = '7_DwdcM8kMwneSBrBd-9Yg'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 11, 'UNSUPPORTED': 55,
            'PARTIAL': 23, 'NOT_RUN': 392}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 54,
              'PARTIAL': 30, 'NOT_RUN': 392}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 8, 'independent SESSION-01 fixture provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'SESSION-01 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 89 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'eighty-nine bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'SESSION-01 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'SESSION-01 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(cases['SESSION-01-P']['status'] == 'PARTIAL' and
                all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS[1:])
                and report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'SESSION-01 status promotion: ' + language)
        positive = load((directory / 'SESSION-01-P-runtime.json').read_bytes())
        require(positive['actual'] == {'verdict': 'ACCEPT',
                'output': {'c2s_sid': SID, 's2c_sid': SID}, 'effects': {}},
                'SESSION-01 core SID observation: ' + language)
        for ident in IDS[1:]:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(observation['actual'] == UNSUPPORTED,
                    'SESSION-01 receiver support: ' + language + '/' + ident)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
