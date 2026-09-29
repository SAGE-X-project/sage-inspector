"""Reassess pinned Go/Rust bounded hop observations."""

from check_current_spec_hop_vectors import check as check_vectors, IDS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/exec-hop'
RUNNER_REVISION = '5a2f74f57199e056f0977454e7f4cb559ad15ef7'
CORE = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '5c74c946c34187dfd5d2e8904eb8a00fd4db0b2794689d62c4d3fc727c04840e'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '32cd8d4ce8fa5641da125314a7a1bbd52dde6c0d9b1c5574940e46e0dc3c26ba'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 3, 'independent signed hop fixtures')
    result = {}
    for language, (repository, revision, binary_sha) in CORE.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': binary_sha} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC and
                {row['id'] for row in manifest['observations']} == set(IDS),
                'hop subject, runner, and observation IDs: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_guard_hop_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'archived hop runner hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == {'PASS': 0, 'FAIL': 0,
                                     'UNSUPPORTED': 0, 'PARTIAL': 3,
                                     'NOT_RUN': 478} and
                report['conformance'] == 'NOT_ESTABLISHED',
                'hop assessment drift: ' + language)
        for ident in IDS:
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            row = next(case for case in report['cases'] if case['id'] == ident)
            require(row['status'] == 'PARTIAL' and
                    row['tracks']['runtime'] == 'PARTIAL' and
                    observation['actual'] == fixture['expected'],
                    'hop observation mismatch: ' + language + '/' + ident)
        result[language] = report['counts']
    return result


if __name__ == '__main__':
    print(check())
