"""Reassess archived Registry lifecycle observations and bounded core gate."""

from check_current_spec_reg03_vectors import check as check_vectors, IDS, ORIGINAL
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/reg03'
RUNNER_REVISION = 'dfd2613d9d1ec897a6619d26498e70dba9ae8457'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           'f655775a1ea7879219d115cd2d346d70dce9977929456f4450b32586dd9f8c80',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 148,
            'PARTIAL': 33, 'NOT_RUN': 282}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             '9e51172c562a2942b1b4376aa193fa8b84408b3a8c77860b56f56f8733cb31cb',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 147,
              'PARTIAL': 40, 'NOT_RUN': 282}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}
DID = ('did:sage:eip155:1:0xabababababababababababababababababababab:'
       'alice')


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == (5, 2),
            'independent REG-03 lifecycle fixture provenance')
    outcomes = {}
    for language, (repository, revision, executable_sha, _, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] ==
                    '5bcf511e604579afa63f434013447f44b6858828',
                'REG-03 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 199 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred ninety-nine bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'REG-03 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'REG-03 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'REG-03 unavailable lifecycle API: ' + language + '/' + ident)
        outcomes[language] = counts
    capability = load((base / 'capability/report.json').read_bytes())
    source = root / ORIGINAL
    require(capability['schema_version'] == 1 and
            capability['runner_revision'] == RUNNER_REVISION and
            capability['source_sha256'] == sha(source.read_bytes()) and
            capability['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_id04_capability.py').read_bytes()),
            'REG-03 bounded gate provenance')
    requests = [
        {'id': 'before', 'request': {'action': 'inspect', 'did': DID}},
        {'id': 'mutation', 'request': {'action': 'mutate'}},
        {'id': 'after', 'request': {'action': 'inspect', 'did': DID}},
    ]
    expected = [
        {'id': 'before', 'verdict': 'ACCEPT', 'output': {
            'highest_finalized_version': '0', 'tombstone': False}},
        {'id': 'mutation', 'verdict': 'UNSUPPORTED', 'output': {}},
        {'id': 'after', 'verdict': 'ACCEPT', 'output': {
            'highest_finalized_version': '0', 'tombstone': False}},
    ]
    require(capability['requests'] == requests,
            'bounded mutation request without a deployment write')
    for language, (repository, revision, _, gate_sha, _) in REVISIONS.items():
        require(capability['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': gate_sha} and
                capability['observations'][language] == {
                    'actual': expected, 'stderr': ''},
                'core mutation capability and unchanged local journal: ' + language)
    return outcomes


if __name__ == '__main__':
    print(check())
