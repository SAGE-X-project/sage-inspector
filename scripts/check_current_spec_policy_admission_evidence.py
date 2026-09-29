"""Reassess pinned Go/Rust signed policy-admission denials."""

from check_current_spec_policy_admission_vectors import check as check_vectors, CASES, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/exec-policy-admission'
RUNNER_REVISION = 'cb355601b7ff8d544a2f70e2e236f9f406bb644f'
CORE = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '86820fb3c36df17194398ce4247fe6dd3fac0efc12a9af1d84a6f87a308cfc88'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             '0b7206b639fb2ae7b6e75bcb0c6d34b12be2c51b7707bf22929651b0ad650e6f'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 2, 'independent signed policy fixtures')
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
                {ident for ident, _ in CASES},
                'policy subject and runner identity: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'archived policy runner hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == {'PASS': 0, 'FAIL': 0,
                                     'UNSUPPORTED': 0, 'PARTIAL': 2,
                                     'NOT_RUN': 479} and
                report['conformance'] == 'NOT_ESTABLISHED',
                'policy assessment drift: ' + language)
        for ident, _ in CASES:
            fixture = load((root / 'vectors/0.10.0/current-spec' /
                            (ident + '.json')).read_bytes())
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            row = next(case for case in report['cases'] if case['id'] == ident)
            require(row['status'] == 'PARTIAL' and
                    row['tracks']['runtime'] == 'PARTIAL' and
                    observation['actual'] == fixture['expected'],
                    'policy observation mismatch: ' + language + '/' + ident)
        result[language] = report['counts']
    return result


if __name__ == '__main__':
    print(check())
