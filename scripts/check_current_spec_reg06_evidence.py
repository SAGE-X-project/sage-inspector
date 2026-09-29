"""Reassess archived eip155 observations without admitting deployment claims."""

from check_current_spec_reg06_vectors import check as check_vectors, IDS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/reg06'
RUNNER_REVISION = 'b9e60759850a18cdea4545f0caf19b862f991845'
REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 164,
            'PARTIAL': 33, 'NOT_RUN': 266}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 163,
              'PARTIAL': 40, 'NOT_RUN': 266}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}
SOURCE_FILES = {
    'go': {
        'pkg/agent/did/ethereum/agentcard_client.go':
            '8c20798934c80a518f556b645e5cd2abfbbe0f55b92bc89d739a97db6a718b29',
        'pkg/agent/registry010/gate.go':
            '31e5e7f7a57fb0b9e37d9d6b57532c2ff33b80c859302aa51d5b25ea531817c5',
    },
    'rust': {
        'src/registry010/mod.rs':
            '116339fc66cef93a723958f2ef6ba5f93493c02c7a333b2c3dfb97fb12f76e03',
    },
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root)[:2] == (5, 2),
            'independent REG-06 fixture provenance')
    outcomes = {}
    for language, (repository, revision, executable_sha, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC,
                'REG-06 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 215 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'two hundred fifteen bounded runtime observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'REG-06 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'REG-06 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    cases[ident]['tracks'] == {
                        'runtime': 'UNSUPPORTED',
                        'deployment_review': 'NOT_RUN'} and
                    observation['actual'] == UNSUPPORTED,
                    'REG-06 unavailable runtime and unobserved deployment: ' +
                    language + '/' + ident)
        outcomes[language] = counts
    review = load((base / 'source-review.json').read_bytes())
    require(review['schema_version'] == 1 and
            review['spec_revision'] == SPEC and
            review['review_type'] == 'pinned-source-prerequisite-review' and
            review['deployment_identity'] is None and
            review['deployment_observation'] is None and
            review['review_verdict'] == 'NOT_ESTABLISHED' and
            set(review['subjects']) == set(REVISIONS),
            'source review cannot substitute for a deployed binding')
    for language, (repository, revision, _, _) in REVISIONS.items():
        row = review['subjects'][language]
        require(row['repository'] == repository and row['revision'] == revision
                and row['files'] == SOURCE_FILES[language]
                and type(row['finding']) is str and row['finding'],
                'pinned REG-06 source review: ' + language)
    return outcomes


if __name__ == '__main__':
    print(check())
