"""Reassess preserved core replay and recovery observations."""

from check_current_spec_exec05_replay_vectors import check as check_vectors, IDS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/exec05'
RUNNER_REVISION = '12ea75a80f24e55ab8c7c01ac3d53a7e5a600ec2'
REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '3000536462f12484e88f52f182561c413bfdd6e68a60362a6c1cf8c510494997'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             'c7e27bf0f212fc53960e4483be7c15a470fe874492ef17e7d594e06292e62202'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 4, 'independent replay fixtures')
    results = {}
    for language, (repository, revision, executable_sha) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC and
                len(manifest['observations']) == 4 and
                [row['id'] for row in manifest['observations']] == sorted(IDS),
                'replay subject, runner, and case identity: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_guard_dispatch_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'replay runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == {'PASS': 0, 'FAIL': 0, 'UNSUPPORTED': 0,
                                     'PARTIAL': 4, 'NOT_RUN': 477} and
                report['conformance'] == 'NOT_ESTABLISHED',
                'replay assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'PARTIAL' and
                    cases[ident]['tracks']['runtime'] == 'PARTIAL' and
                    observation['actual'] == fixture['expected'],
                    'replay observation mismatch: ' + language + '/' + ident)
        results[language] = report['counts']
    return results


if __name__ == '__main__':
    print(check())
