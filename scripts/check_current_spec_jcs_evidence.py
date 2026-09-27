"""Recheck preserved Go/Rust duplicate-key observations and runner provenance."""

import json
from pathlib import Path

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same


BASE = ROOT / 'docs/evidence/current-spec/jcs-duplicate'
CORE_REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           'FAIL'),
    'rust': ('SAGE-X-project/rs-sage-core', 'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             'PARTIAL'),
}


def check(base=BASE, root=ROOT):
    outcomes = {}
    for language, (repository, revision, status) in CORE_REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision,
                'core subject identity: ' + language)
        require(len(manifest['observations']) == 1 and
                manifest['observations'][0]['id'] == 'JCS-01-N01',
                'single bounded JCS observation: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'preserved runner identity: ' + language)
        report = assess(root, directory)
        archived = load((directory / 'assessed.json').read_bytes())
        require(same(report, archived), 'assessed report drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(cases['JCS-01-N01']['status'] == status and
                report['counts'][status] == 1 and report['counts']['NOT_RUN'] == 480
                and report['conformance'] == 'NOT_ESTABLISHED',
                'JCS status promotion: ' + language)
        outcomes[language] = status
    return outcomes


if __name__ == '__main__':
    print(check())
