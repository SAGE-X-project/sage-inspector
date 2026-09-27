"""Reassess pinned HPKE-05 record and provisional-state observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_hpke05_vectors import check as check_vectors, IDS, PLAINTEXT


BASE = ROOT / 'docs/evidence/current-spec/hpke05'
RUNNER_REVISION = 'f6aabd7eaaa3bf148503f5d3c99a4d124024ff01'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 11, 'UNSUPPORTED': 43,
            'PARTIAL': 22, 'NOT_RUN': 405}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 42,
              'PARTIAL': 29, 'NOT_RUN': 405}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'independent HPKE-05 vector provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'HPKE-05 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 76 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('HPKE-05-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'seventy-six bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'HPKE-05 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'HPKE-05 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(cases['HPKE-05-P']['status'] == 'PARTIAL' and
                all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS[1:])
                and report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'HPKE-05 status promotion: ' + language)
        observation = load((directory / 'HPKE-05-P-runtime.json').read_bytes())
        require(observation['actual'] == {'verdict': 'ACCEPT',
                'output': {'plaintext_hex': PLAINTEXT}, 'effects': {}},
                'HPKE-05 first record core observation: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
