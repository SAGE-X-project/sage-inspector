"""Reassess archived web-profile observations and the unbound media rule."""

from check_current_spec_reg08_vectors import check as check_vectors, IDS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/reg08'
RUNNER_REVISION = 'bd6bb8051669958a69ab7957e74b966a8e4c556b'
REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 170,
            'PARTIAL': 33, 'NOT_RUN': 260}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 169,
              'PARTIAL': 40, 'NOT_RUN': 260}),
}
UNSUPPORTED = {'verdict': 'UNSUPPORTED',
               'reason': 'Core primitive adapter does not expose this operation.'}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == (4, 6, 'REG-08-N04'),
            'independent REG-08 fixtures and unresolved media-type provenance')
    outcomes = {}
    for language, (repository, revision, executable_sha, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC,
                'REG-08 subject, runner, and spec identity: ' + language)
        require(len(manifest['observations']) == 221 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations'])
                and not any(row['id'] == 'REG-08-N04'
                            for row in manifest['observations']),
                'two hundred twenty-one bounded observations and no invented N04: ' +
                language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'REG-08 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'REG-08 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'UNSUPPORTED' and
                    observation['actual'] == UNSUPPORTED,
                    'REG-08 unavailable complete authority boundary: ' +
                    language + '/' + ident)
        require(cases['REG-08-N04']['status'] == 'NOT_RUN' and
                cases['REG-08-N04']['tracks'] == {'runtime': 'NOT_RUN'},
                'REG-08 media type remains an unresolved normative decision')
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
