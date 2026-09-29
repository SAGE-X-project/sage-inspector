"""Reassess pinned Client UNKNOWN and MCP pending observations."""

from check_current_spec_exec_pending_vectors import check as check_vectors, IDS, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/exec-pending'
RUNNER_REVISION = '596dd1492ddefc97dfa49129fef9f4a01dfd39c5'
CORE = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}
BINARIES = {
    'client': {
        'go': 'db4469f152b78bb603ed50083d151a1003f14dc665bae9dcca08edb6a1b1780d',
        'rust': '4e635b162eddf489feb267a6928efae362a2dd9179677e269ca46efe97f2c6b2'},
    'mcp': {
        'go': '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88',
        'rust': '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f'},
}
BRIDGES = {
    'client': 'current_spec_guard_client_bridge.py',
    'mcp': 'current_spec_primitive_bridge.py',
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 2, 'independent pending-state fixtures')
    result = {}
    for kind, ident in zip(('client', 'mcp'), IDS):
        for language, (repository, revision) in CORE.items():
            directory = base / kind / language
            manifest = load((directory / 'manifest.json').read_bytes())
            require(manifest['subject'] == {
                        'repository': repository, 'revision': revision,
                        'executable_sha256': BINARIES[kind][language]} and
                    manifest['runner_revision'] == RUNNER_REVISION and
                    manifest['spec_revision'] == SPEC and
                    len(manifest['observations']) == 1 and
                    manifest['observations'][0]['id'] == ident,
                    'pending subject and runner identity: ' + kind + '/' + language)
            require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                    manifest['runner_sha256'] and
                    sha((base / 'runner' / BRIDGES[kind]).read_bytes()) ==
                    manifest['adapter_sha256'],
                    'pending runner and bridge hashes: ' + kind + '/' + language)
            report = assess(root, directory)
            require(same(report, load((directory / 'assessed.json').read_bytes())) and
                    report['counts'] == {'PASS': 0, 'FAIL': 0,
                                         'UNSUPPORTED': 0, 'PARTIAL': 1,
                                         'NOT_RUN': 480} and
                    report['conformance'] == 'NOT_ESTABLISHED',
                    'pending assessment drift: ' + kind + '/' + language)
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            case = next(row for row in report['cases'] if row['id'] == ident)
            require(case['status'] == 'PARTIAL' and
                    case['tracks']['runtime'] == 'PARTIAL' and
                    observation['actual'] == fixture['expected'],
                    'pending observation mismatch: ' + kind + '/' + language)
            result[kind + '/' + language] = report['counts']
    return result


if __name__ == '__main__':
    print(check())
