"""Reassess pinned Go and Rust client result-consumption observations."""

from check_current_spec_exec_client_vectors import check as check_vectors, SCENARIOS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/exec-client'
RUNNER_REVISION = 'b76d60fe78611ec1646e22d2b9b894bb3738a9c1'
SUBJECTS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           'db4469f152b78bb603ed50083d151a1003f14dc665bae9dcca08edb6a1b1780d'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '4e635b162eddf489feb267a6928efae362a2dd9179677e269ca46efe97f2c6b2'),
}
SOURCES = {
    'adapter-source/go/main.go':
        'b3540e7301a98bdb2941fa393111060897ac9b7a775cf7f2ed99097580e24991',
    'adapter-source/go/fixtures.go':
        '8f96b84a6171272193e8d2f08e56e8f27982a0d4e73aea0d1c52b9013171a673',
    'adapter-source/rust/guard_client010.rs':
        'a9395eaad3e2789b812359c04b3617c859aa98176d8afffd617de67590d514b9',
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 4, 'independent client consumption fixtures')
    for path, digest in SOURCES.items():
        require(sha((base / path).read_bytes()) == digest,
                'archived client adapter source: ' + path)
    result = {}
    for language, (repository, revision, executable_sha) in SUBJECTS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC and
                len(manifest['observations']) == 4 and
                [row['id'] for row in manifest['observations']] ==
                sorted(SCENARIOS),
                'client subject, runner and case identity: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_guard_client_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'client runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == {'PASS': 0, 'FAIL': 0, 'UNSUPPORTED': 0,
                                     'PARTIAL': 4, 'NOT_RUN': 477} and
                report['conformance'] == 'NOT_ESTABLISHED',
                'client assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in SCENARIOS:
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'PARTIAL' and
                    cases[ident]['tracks']['runtime'] == 'PARTIAL' and
                    observation['actual'] == fixture['expected'],
                    'client observation mismatch: ' + language + '/' + ident)
        result[language] = report['counts']
    return result


if __name__ == '__main__':
    print(check())
