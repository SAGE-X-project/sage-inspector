"""Recheck the six preserved JCS parser observations and their provenance."""

from pathlib import Path

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/jcs-parser'
EXPECTED = {
    'go': {
        'repository': 'SAGE-X-project/sage',
        'revision': '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
        'statuses': ('FAIL', 'PARTIAL', 'FAIL', 'PARTIAL', 'FAIL', 'FAIL'),
        'counts': {'PASS': 0, 'FAIL': 4, 'UNSUPPORTED': 0,
                   'PARTIAL': 2, 'NOT_RUN': 475},
    },
    'rust': {
        'repository': 'SAGE-X-project/rs-sage-core',
        'revision': 'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
        'statuses': ('PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'FAIL', 'FAIL'),
        'counts': {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 0,
                   'PARTIAL': 4, 'NOT_RUN': 475},
    },
}


def check(base=BASE, root=ROOT):
    outcomes = {}
    ids = [f'JCS-01-N{number:02d}' for number in range(1, 7)]
    runner = base / 'runner/run_current_spec_cases.py'
    adapter = base / 'runner/current_spec_primitive_bridge.py'
    for language, expected in EXPECTED.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        subject = manifest['subject']
        require(subject['repository'] == expected['repository'] and
                subject['revision'] == expected['revision'],
                'core subject identity: ' + language)
        require(manifest['runner_revision'] ==
                'ebc359d9bcc2022d5d7a22606c52b50fd72d3c32',
                'Inspector runner revision: ' + language)
        require([row['id'] for row in manifest['observations']] == ids and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'six bounded JCS observations: ' + language)
        require(sha(runner.read_bytes()) == manifest['runner_sha256'] and
                sha(adapter.read_bytes()) == manifest['adapter_sha256'],
                'preserved runner identity: ' + language)
        report = assess(root, directory)
        archived = load((directory / 'assessed.json').read_bytes())
        require(same(report, archived), 'assessed report drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        statuses = tuple(cases[ident]['status'] for ident in ids)
        require(statuses == expected['statuses'] and
                report['counts'] == expected['counts'] and
                report['conformance'] == 'NOT_ESTABLISHED',
                'JCS status promotion: ' + language)
        outcomes[language] = dict(zip(ids, statuses))
    return outcomes


if __name__ == '__main__':
    print(check())
