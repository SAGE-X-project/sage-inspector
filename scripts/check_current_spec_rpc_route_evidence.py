"""Reassess pinned guarded RPC route exclusions."""

from check_current_spec_rpc_route_vectors import check as check_vectors, IDS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/exec-rpc-routes'
RUNNER_REVISION = '7db7ade6003308bda87309c555f0e30f53752816'
CORE = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '9f34db48de7c05288ef3d56e92db10e4304b282151ed4dc3cc1a290a70afb859'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             'ab47307ee856fd9599e1136aa0c168959eebebd70bb7dd8548d34fa8e80dc3f1'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 2, 'independent guarded RPC routes')
    result = {}
    for language, (repository, revision, executable) in CORE.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC and
                {row['id'] for row in manifest['observations']} ==
                {ident for ident, _ in IDS},
                'RPC route subject and runner identity: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_guard_rpc_route_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'archived RPC route runner hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == {'PASS': 0, 'FAIL': 0,
                                     'UNSUPPORTED': 0, 'PARTIAL': 2,
                                     'NOT_RUN': 479} and
                report['conformance'] == 'NOT_ESTABLISHED',
                'RPC route assessment drift: ' + language)
        for ident, _ in IDS:
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            row = next(case for case in report['cases'] if case['id'] == ident)
            require(row['status'] == 'PARTIAL' and
                    row['tracks']['runtime'] == 'PARTIAL' and
                    observation['actual'] == fixture['expected'],
                    'RPC route observation mismatch: ' + language + '/' + ident)
        result[language] = report['counts']
    return result


if __name__ == '__main__':
    print(check())
