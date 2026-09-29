"""Reassess pinned local replay refusal after key withdrawal."""

from check_current_spec_key_rotation_vectors import check as check_vectors, ID, SPEC
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/exec-key-rotation'
RUNNER_REVISION = 'c9bc3852d300e6b09067ae48eaf224702a8a18da'
CORE = {
    'go': ('SAGE-X-project/sage',
           '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           '3000536462f12484e88f52f182561c413bfdd6e68a60362a6c1cf8c510494997'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             'c7e27bf0f212fc53960e4483be7c15a470fe874492ef17e7d594e06292e62202'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 1, 'independent rotated-key fixture')
    result = {}
    for language, (repository, revision, executable) in CORE.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject'] == {
                    'repository': repository, 'revision': revision,
                    'executable_sha256': executable} and
                manifest['runner_revision'] == RUNNER_REVISION and
                manifest['spec_revision'] == SPEC and
                len(manifest['observations']) == 1 and
                manifest['observations'][0]['id'] == ID,
                'rotation subject and runner identity: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_guard_dispatch_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'archived rotation runner hashes: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())) and
                report['counts'] == {'PASS': 0, 'FAIL': 0,
                                     'UNSUPPORTED': 0, 'PARTIAL': 1,
                                     'NOT_RUN': 480} and
                report['conformance'] == 'NOT_ESTABLISHED',
                'rotation assessment drift: ' + language)
        fixture = load((root / 'vectors/0.10.0/current-spec' /
                        (ID + '.json')).read_bytes())
        observation = load((directory / (ID + '-runtime.json')).read_bytes())
        row = next(case for case in report['cases'] if case['id'] == ID)
        require(row['status'] == 'PARTIAL' and
                row['tracks']['runtime'] == 'PARTIAL' and
                observation['actual'] == fixture['expected'],
                'rotation observation mismatch: ' + language)
        result[language] = report['counts']
    return result


if __name__ == '__main__':
    print(check())
