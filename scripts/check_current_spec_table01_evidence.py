"""Reassess archived DID key dereference observations."""

from check_current_spec_table01_vectors import check as check_vectors, IDS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/table01'
RUNNER_REVISION = 'b256d8335e420596c37c2befdae6f9c635638ad9'
REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 199,
            'PARTIAL': 33, 'NOT_RUN': 231}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 198,
              'PARTIAL': 40, 'NOT_RUN': 231}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == (4, 2, 8), 'independent TABLE-01 fixtures')
    source_review = load((base / 'source-review.json').read_bytes())
    require(source_review['schema_version'] == 1 and
            source_review['spec_revision'] == SPEC and
            source_review['sources'] == {
                'spec/11-registries.md':
                    'eb673391143bd4ed9283ee8a6a578aeb44e0018a78f6d994ebfeb70160757bf4',
                'spec/00-overview.md':
                    '82493ba53f38cc783a2e76ffab3a70dc069b6ac3e534c7422840369fc90d9978'} and
            source_review['actual_proposal_evidence'] is None and
            source_review['document_review_status'] == 'NOT_RUN',
            'pinned source review does not claim an adopted registration')
    outcomes = {}
    for language, (repository, revision, executable_sha, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC,
                'TABLE-01 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 250 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'two hundred fifty bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'TABLE-01 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'TABLE-01 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    cases[ident]['tracks'] == {
                        'runtime': 'UNSUPPORTED', 'document_review': 'NOT_RUN'} and
                    observation['actual'] == UNSUPPORTED,
                    'TABLE-01 unavailable registry value governance: ' + language + '/' + ident)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
