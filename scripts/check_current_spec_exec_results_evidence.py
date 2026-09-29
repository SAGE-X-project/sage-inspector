"""Reassess preserved manifest, result, and MCP observations."""

from check_current_spec_exec_results_vectors import check as check_vectors, IDS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/exec-results'
RUNNER_REVISION = 'd9d7b7f536c72e97d829759428b0eccacd39d1e5'
REVISIONS = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 9, 'independent result and MCP fixtures')
    results = {}
    for language, (repository, revision, executable_sha) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC and
                len(manifest['observations']) == 9 and
                [row['id'] for row in manifest['observations']] == sorted(IDS),
                'result subject, runner, and case identity: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'result runner and bridge hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == {'PASS': 0, 'FAIL': 0, 'UNSUPPORTED': 0,
                                     'PARTIAL': 9, 'NOT_RUN': 472} and
                report['conformance'] == 'NOT_ESTABLISHED',
                'result assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        for ident in IDS:
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(cases[ident]['status'] == 'PARTIAL' and
                    cases[ident]['tracks']['runtime'] == 'PARTIAL' and
                    observation['actual'] == fixture['expected'],
                    'result observation mismatch: ' + language + '/' + ident)
        results[language] = report['counts']
    return results


if __name__ == '__main__':
    print(check())
