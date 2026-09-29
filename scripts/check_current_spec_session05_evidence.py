"""Reassess primitive and retained-record SESSION-05 evidence separately."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_session05_vectors import check as check_vectors, IDS
from run_current_spec_session05_state import check as check_state


BASE = ROOT / 'docs/evidence/current-spec/session05'
PRIMITIVE_RUNNER_REVISION = '36bf33fd115994b63137f5c3daa23ada18e9acee'
STATE_RUNNER_REVISION = '6b27f9861921dcca2cb5a5e2e47796f962a2a57a'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           'c2af9df4ce117fe813554ef7f4ef8e4f583cbe21e5ecc81550543414726a3e0c',
           {'PASS': 0, 'FAIL': 11, 'UNSUPPORTED': 68,
            'PARTIAL': 33, 'NOT_RUN': 369}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             'f35d8c5412cbee6e9c4dcb2bc2b5122fea437e747186026eab3f1098a91b3e4d',
             {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 67,
              'PARTIAL': 40, 'NOT_RUN': 369}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'independent SESSION-05 fixture provenance')
    require(sha((base / 'runner/run_current_spec_session05_state.py').read_bytes()) ==
            sha((root / 'scripts/run_current_spec_session05_state.py').read_bytes()),
            'stateful runner source snapshot')
    state = load((base / 'state/report.json').read_bytes())
    require(state['runner_revision'] == STATE_RUNNER_REVISION and
            state['runner_sha256'] == sha((base /
                'runner/run_current_spec_session05_state.py').read_bytes()),
            'stateful runner identity')
    state_statuses = check_state(root, base / 'state')
    outcomes = {}
    for language, (repository, revision, state_binary_hash, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == PRIMITIVE_RUNNER_REVISION,
                'SESSION-05 primitive subject identity: ' + language)
        require(len(manifest['observations']) == 112 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred twelve bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'SESSION-05 primitive runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'SESSION-05 primitive assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS),
                'primitive adapter falsely claims stateful support: ' + language)
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(observation['actual'] == {
                'verdict': 'UNSUPPORTED',
                'reason': 'Core primitive adapter does not expose this operation.'},
                'SESSION-05 primitive observation: ' + language + '/' + ident)
        require(state['subjects'][language] == {
            'repository': repository, 'revision': revision,
            'executable_sha256': state_binary_hash},
            'stateful subject binary pin: ' + language)
        require(state_statuses[language] == {
            'SESSION-05-P': 'PARTIAL', 'SESSION-05-N01': 'UNSUPPORTED',
            'SESSION-05-N02': 'PARTIAL', 'SESSION-05-N03': 'PARTIAL',
            'SESSION-05-N04': 'UNSUPPORTED'},
            'stateful case status: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
