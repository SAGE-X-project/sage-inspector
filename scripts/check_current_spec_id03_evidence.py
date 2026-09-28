"""Reassess ID-03 unsupported cases and limited retained-core key state."""

import hashlib
import json

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_id03_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/id03'
RUNNER_REVISION = '6954cd5cca7267ab9bb9c528fa6ce5085502f827'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           'f655775a1ea7879219d115cd2d346d70dce9977929456f4450b32586dd9f8c80',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 83,
            'PARTIAL': 33, 'NOT_RUN': 347}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '9e51172c562a2942b1b4376aa193fa8b84408b3a8c77860b56f56f8733cb31cb',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 82,
              'PARTIAL': 40, 'NOT_RUN': 347}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}
STATE_IDS = ('kem-required', 'exact-signing-url', 'revoked-signing',
             'expiry-equality', 'changed-algorithm')


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 6, 'independent ID-03 fixture provenance')
    outcomes = {}
    for language, (repository, revision, _, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'ID-03 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 134 and
                [row['id'] for row in manifest['observations'] if
                 row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred thirty-four bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'ID-03 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'ID-03 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'ID-03 unsupported named-key operation: ' + language + '/' + ident)
        outcomes[language] = counts
    state = load((base / 'state/report.json').read_bytes())
    source_path = root / 'vectors/0.10.0/registry010.json'
    source = load(source_path.read_bytes())
    source_cases = {row['id']: row for row in source['cases']}
    require(state['schema_version'] == 1 and
            state['runner_revision'] == RUNNER_REVISION and
            state['source_sha256'] == sha(source_path.read_bytes()) and
            state['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_id03_state.py').read_bytes()) and
            len(state['scenarios']) == 10,
            'ID-03 retained-state provenance')
    for language, (repository, revision, executable_sha, _) in REVISIONS.items():
        require(state['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha},
                'ID-03 retained-state executable identity: ' + language)
        rows = [row for row in state['scenarios'] if row['language'] == language]
        require([row['id'] for row in rows] == list(STATE_IDS),
                'ID-03 retained-state case order: ' + language)
        for row in rows:
            case = source_cases[row['id']]
            envelopes = [{'id': str(index), 'request': step['request']}
                         for index, step in enumerate(case['steps'])]
            raw = ''.join(json.dumps(item, separators=(',', ':')) + '\n'
                          for item in envelopes).encode()
            expected = [{'id': str(index), **step['expected']}
                        for index, step in enumerate(case['steps'])]
            require(row['request_sha256'] == hashlib.sha256(raw).hexdigest() and
                    row['actual'] == expected and row['stderr'] == '',
                    'ID-03 retained-state result: ' + language + '/' + row['id'])
    return outcomes


if __name__ == '__main__':
    print(check())
