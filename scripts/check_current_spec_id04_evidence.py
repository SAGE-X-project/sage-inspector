"""Reassess ID-04 mutation gaps without promoting an unsupported gate."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_id04_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/id04'
RUNNER_REVISION = '3b2aa8c3f0d160a5dfeca41db4a16231a9defe88'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           'f655775a1ea7879219d115cd2d346d70dce9977929456f4450b32586dd9f8c80',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 87,
            'PARTIAL': 33, 'NOT_RUN': 343}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '9e51172c562a2942b1b4376aa193fa8b84408b3a8c77860b56f56f8733cb31cb',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 86,
              'PARTIAL': 40, 'NOT_RUN': 343}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}
DID = ('did:sage:eip155:1:0xabababababababababababababababababababab:'
       'alice')


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 4, 'independent ID-04 fixture provenance')
    outcomes = {}
    for language, (repository, revision, executable_sha, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'ID-04 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 138 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred thirty-eight bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'ID-04 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'ID-04 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'ID-04 unsupported lifecycle operation: ' + language + '/' + ident)
        outcomes[language] = counts
    capability = load((base / 'capability/report.json').read_bytes())
    source_path = root / 'vectors/0.10.0/registry-scenarios/registry-mutations.json'
    require(capability['schema_version'] == 1 and
            capability['runner_revision'] == RUNNER_REVISION and
            capability['source_sha256'] == sha(source_path.read_bytes()) and
            capability['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_id04_capability.py').read_bytes()),
            'ID-04 mutation capability provenance')
    requests = [
        {'id': 'before', 'request': {'action': 'inspect', 'did': DID}},
        {'id': 'mutation', 'request': {'action': 'mutate'}},
        {'id': 'after', 'request': {'action': 'inspect', 'did': DID}},
    ]
    require(capability['requests'] == requests, 'ID-04 bounded mutation request')
    expected = [
        {'id': 'before', 'verdict': 'ACCEPT', 'output': {
            'highest_finalized_version': '0', 'tombstone': False}},
        {'id': 'mutation', 'verdict': 'UNSUPPORTED', 'output': {}},
        {'id': 'after', 'verdict': 'ACCEPT', 'output': {
            'highest_finalized_version': '0', 'tombstone': False}},
    ]
    for language, (repository, revision, executable_sha, _) in REVISIONS.items():
        require(capability['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                capability['observations'][language] == {
                    'actual': expected, 'stderr': ''},
                'ID-04 core mutation capability: ' + language)
    return outcomes


if __name__ == '__main__':
    print(check())
