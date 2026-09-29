"""Reassess pinned SESSION-06 primitive and retained-record observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_session06_vectors import check as check_vectors, IDS
from run_current_spec_session06_state import check as check_state


BASE = ROOT / 'docs/evidence/current-spec/session06'
RUNNER_REVISION = '52be3d64f0fd18c7c5a325e4c7f2b4ce3e17854c'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           'c2af9df4ce117fe813554ef7f4ef8e4f583cbe21e5ecc81550543414726a3e0c',
           {'PASS': 0, 'FAIL': 11, 'UNSUPPORTED': 74,
            'PARTIAL': 33, 'NOT_RUN': 363}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             'f35d8c5412cbee6e9c4dcb2bc2b5122fea437e747186026eab3f1098a91b3e4d',
             {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 73,
              'PARTIAL': 40, 'NOT_RUN': 363}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 6, 'independent SESSION-06 fixture provenance')
    require(sha((base / 'runner/run_current_spec_session06_state.py').read_bytes()) ==
            sha((root / 'scripts/run_current_spec_session06_state.py').read_bytes()),
            'stateful runner source snapshot')
    state = load((base / 'state/report.json').read_bytes())
    require(state['runner_revision'] == RUNNER_REVISION and
            state['runner_sha256'] == sha((base /
                'runner/run_current_spec_session06_state.py').read_bytes()),
            'stateful closure runner identity')
    state_statuses = check_state(root, base / 'state')
    outcomes = {}
    for language, (repository, revision, state_binary_hash, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'SESSION-06 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 118 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred eighteen bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'SESSION-06 primitive runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'SESSION-06 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS),
                'primitive adapter falsely claims closure support: ' + language)
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(observation['actual'] == {
                'verdict': 'UNSUPPORTED',
                'reason': 'Core primitive adapter does not expose this operation.'},
                'SESSION-06 primitive observation: ' + language + '/' + ident)
        require(state['subjects'][language] == {
            'repository': repository, 'revision': revision,
            'executable_sha256': state_binary_hash},
            'stateful closure subject binary pin: ' + language)
        require(state_statuses[language] == {
            ident: ('PARTIAL' if ident == 'SESSION-06-N05' else 'UNSUPPORTED')
            for ident in IDS}, 'stateful closure case status: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
