"""Recheck preserved positive JCS parser observations and provenance."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/jcs-positive'
SUBJECTS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7'),
    'rust': ('SAGE-X-project/rs-sage-core', 'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396'),
}


def check(base=BASE, root=ROOT):
    outcomes = {}
    for language, (repository, revision) in SUBJECTS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] ==
                '66174ec64e466c63036f5509dad4d090ab293e25',
                'positive JCS subject/runner identity: ' + language)
        require(len(manifest['observations']) == 1 and
                manifest['observations'][0]['id'] == 'JCS-01-P' and
                manifest['observations'][0]['track'] == 'runtime',
                'one bounded positive JCS observation: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'],
                'positive JCS runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'positive JCS assessment drift: ' + language)
        case = next(row for row in report['cases'] if row['id'] == 'JCS-01-P')
        require(case['status'] == 'PARTIAL' and
                report['counts'] == {'PASS': 0, 'FAIL': 0, 'UNSUPPORTED': 0,
                                     'PARTIAL': 1, 'NOT_RUN': 480} and
                report['conformance'] == 'NOT_ESTABLISHED',
                'positive JCS status promotion: ' + language)
        outcomes[language] = case['status']
    return outcomes


if __name__ == '__main__':
    print(check())
