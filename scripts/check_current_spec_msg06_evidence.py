"""Reassess pinned MSG-06 failure observations and their limited scope."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_msg06_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/msg06'
RUNNER_REVISION = '8851a0fa86ae3bed4fbc3803d7a0c5fd7c052001'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 9, 'UNSUPPORTED': 26,
            'PARTIAL': 17, 'NOT_RUN': 429}, 'FAIL'),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 2, 'UNSUPPORTED': 26,
              'PARTIAL': 24, 'NOT_RUN': 429}, 'PARTIAL'),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 4, 'independent MSG-06 vector provenance')
    expected = load((root / 'vectors/0.10.0/current-spec/MSG-06-P.json')
                    .read_bytes())['expected']['output']
    outcomes = {}
    for language, (repository, revision, counts, positive_status) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'MSG-06 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 52 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('MSG-06-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'fifty-two bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'MSG-06 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'MSG-06 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        require(cases['MSG-06-P']['status'] == positive_status and
                all(cases[ident]['status'] == 'UNSUPPORTED' for ident in IDS[1:])
                and report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'MSG-06 status promotion: ' + language)
        observed = load((directory / 'MSG-06-P-runtime.json').read_bytes())['actual']
        require(observed['verdict'] == 'ACCEPT' and
                observed['output']['digest_valid'] is True and
                observed['effects'] == {}, 'MSG-06 primitive observation')
        actual_base = bytes.fromhex(observed['output']['base_hex'])
        expected_base = bytes.fromhex(expected['base_hex'])
        require((actual_base == expected_base if language == 'rust' else
                 actual_base == expected_base.replace(
                     b';tag="sage-0.10.0"', b'')),
                'MSG-06 response signature base: ' + language)
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
