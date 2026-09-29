"""Reassess signed pending, terminal race, and expiry observations."""

from check_current_spec_exec_result_state_vectors import check as check_vectors, IDS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/exec-result-state'
RUNNER_REVISION = '445fc8dd9a4dea452be866c220b9ed75c2f710fd'
REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '9f34db48de7c05288ef3d56e92db10e4304b282151ed4dc3cc1a290a70afb859'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             'ab47307ee856fd9599e1136aa0c168959eebebd70bb7dd8548d34fa8e80dc3f1'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 3, 'independent signed-result lifecycle fixtures')
    results = {}
    for language, (repository, revision, executable_sha) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC and
                len(manifest['observations']) == 3 and
                [row['id'] for row in manifest['observations']] == sorted(IDS),
                'signed-result subject, runner, and case identity: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_guard_results_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'signed-result runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == {'PASS': 0, 'FAIL': 0, 'UNSUPPORTED': 0,
                                     'PARTIAL': 3, 'NOT_RUN': 478} and
                report['conformance'] == 'NOT_ESTABLISHED',
                'signed-result assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'PARTIAL' and
                    cases[ident]['tracks']['runtime'] == 'PARTIAL' and
                    observation['actual'] == fixture['expected'],
                    'signed-result observation mismatch: ' + language + '/' + ident)
        results[language] = report['counts']
    return results


if __name__ == '__main__':
    print(check())
