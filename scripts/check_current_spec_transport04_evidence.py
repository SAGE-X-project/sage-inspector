"""Reassess receive-transaction gaps and isolated AEAD tag observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_transport04_vectors import check as check_vectors, IDS
from run_current_spec_transport04_tag import input_case


BASE = ROOT / 'docs/evidence/current-spec/transport04'
RUNNER_REVISION = '365054f21461e7f1501d3bf9829dd2496fe7259c'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 125,
            'PARTIAL': 33, 'NOT_RUN': 305}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 124,
              'PARTIAL': 40, 'NOT_RUN': 305}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'declarative TRANSPORT-04 fixture provenance')
    outcomes = {}
    for language, (repository, revision, executable_sha, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] ==
                    '5bcf511e604579afa63f434013447f44b6858828',
                'TRANSPORT-04 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 176 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'one hundred seventy-six bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'TRANSPORT-04 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'TRANSPORT-04 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'TRANSPORT-04 unavailable receive transaction: ' +
                    language + '/' + ident)
        outcomes[language] = counts
    tag = load((base / 'tag/report.json').read_bytes())
    require(tag['schema_version'] == 1 and
            tag['runner_revision'] == RUNNER_REVISION and
            tag['source_sha256'] ==
                sha((root / 'vectors/0.10.0/session-records.json').read_bytes()) and
            tag['scenario_sha256'] ==
                sha((root / 'vectors/0.10.0/transport04-scenarios.json').read_bytes()) and
            tag['runner_sha256'] ==
                sha((base / 'runner/run_current_spec_transport04_tag.py').read_bytes()) and
            tag['bridge_sha256'] ==
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) and
            tag['input'] == input_case(root),
            'TRANSPORT-04 failed-tag primitive provenance')
    for language, (repository, revision, executable_sha, _) in REVISIONS.items():
        require(tag['subjects'][language] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                tag['observations'][language] == {
                    'schema_version': 1, 'case_id': 'TRANSPORT-04-N03-tag',
                    'verdict': 'REJECT', 'output': {}},
                'TRANSPORT-04 bounded AEAD rejection: ' + language)
    return outcomes


if __name__ == '__main__':
    print(check())
