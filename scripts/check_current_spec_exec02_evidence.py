"""Reassess preserved original-request and policy commitment observations."""

from check_current_spec_exec02_vectors import check as check_vectors, IDS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/exec02'
RUNNER_REVISION = '6b56a3a425af6e5440f61da21d3e2920696bb174'
REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
           {'PASS': 0, 'FAIL': 18, 'UNSUPPORTED': 220,
            'PARTIAL': 37, 'NOT_RUN': 206}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f',
             {'PASS': 0, 'FAIL': 12, 'UNSUPPORTED': 219,
              'PARTIAL': 44, 'NOT_RUN': 206}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 4, 'independent EXEC-02 fixtures')
    outcomes = {}
    for language, (repository, revision, executable_sha, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC and
                len(manifest['observations']) == 275 and
                [row['id'] for row in manifest['observations']
                 if row['id'] in IDS] == sorted(IDS),
                'EXEC-02 subject, runner, and case identity: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'EXEC-02 runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'EXEC-02 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'PARTIAL' and
                    cases[ident]['tracks']['runtime'] == 'PARTIAL' and
                    observation['actual'] == fixture['expected'] and
                    observation['actual']['effects'] == {},
                    'EXEC-02 primitive-only observation: ' + language + '/' + ident)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
