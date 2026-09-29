"""Reassess pinned HPKE-03 transcript and combiner observations."""

from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from check_current_spec_hpke03_vectors import check as check_vectors, IDS


BASE = ROOT / 'docs/evidence/current-spec/hpke03'
RUNNER_REVISION = '0a47a93ecf20ce4831c01539ef1300035c3de803'
OLD_SEED = '4b4e39761359b9efab0788a58015390fdece0d4cbc9499bda7e6f0f0af1d6541'
ZERO_SEED = '4ad3f18137516dd443904418c4dd354efdc0074c30e3394f23dad7172efe8f6a'
REVISIONS = {
    'go': ('SAGE-X-project/sage', '49379baadc6baec9ca8b4bb7d15bf43d65144bd7',
           {'PASS': 0, 'FAIL': 11, 'UNSUPPORTED': 36,
            'PARTIAL': 19, 'NOT_RUN': 415}),
    'rust': ('SAGE-X-project/rs-sage-core',
             'ef63d76b88fe4d6ddbc7ae0fcfdbce7beab4d396',
             {'PASS': 0, 'FAIL': 5, 'UNSUPPORTED': 35,
              'PARTIAL': 26, 'NOT_RUN': 415}),
}


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 5, 'independent HPKE-03 vector provenance')
    outcomes = {}
    for language, (repository, revision, counts) in REVISIONS.items():
        directory = base / language
        manifest = load((directory / 'manifest.json').read_bytes())
        require(manifest['subject']['repository'] == repository and
                manifest['subject']['revision'] == revision and
                manifest['runner_revision'] == RUNNER_REVISION,
                'HPKE-03 subject/runner identity: ' + language)
        require(len(manifest['observations']) == 66 and
                [row['id'] for row in manifest['observations'] if
                 row['id'].startswith('HPKE-03-')] == sorted(IDS) and
                all(row['track'] == 'runtime' for row in manifest['observations']),
                'sixty-six bounded observations: ' + language)
        require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
                manifest['runner_sha256'] and
                sha((base / 'runner/current_spec_primitive_bridge.py').read_bytes()) ==
                manifest['adapter_sha256'], 'HPKE-03 runner hash: ' + language)
        report = assess(root, directory)
        require(same(report, load((directory / 'assessed.json').read_bytes())),
                'HPKE-03 assessment drift: ' + language)
        cases = {row['id']: row for row in report['cases']}
        expected = {'HPKE-03-P': 'FAIL', 'HPKE-03-N01':
                    'UNSUPPORTED' if language == 'go' else 'FAIL',
                    'HPKE-03-N02': 'UNSUPPORTED',
                    'HPKE-03-N03': 'UNSUPPORTED', 'HPKE-03-N04': 'FAIL'}
        require(all(cases[ident]['status'] == status for ident, status in
                    expected.items()) and report['counts'] == counts and
                report['conformance'] == 'NOT_ESTABLISHED',
                'HPKE-03 status promotion: ' + language)
        for ident, output in (('HPKE-03-P', {'seed_hex': OLD_SEED}),
                              ('HPKE-03-N04', {'seed_hex': ZERO_SEED})):
            observation = load((directory / (ident + '-runtime.json')).read_bytes())
            require(observation['actual'] == {
                        'verdict': 'ACCEPT', 'output': output, 'effects': {}},
                    'HPKE-03 combiner observation: ' + language + '/' + ident)
        zero = load((directory / 'HPKE-03-N01-runtime.json').read_bytes())
        if language == 'rust':
            require(zero['actual'] == {'verdict': 'ACCEPT',
                    'output': {'shared_secret_hex': '00' * 32}, 'effects': {}},
                    'HPKE-03 zero X25519 observation')
        else:
            require(zero['actual']['verdict'] == 'UNSUPPORTED',
                    'HPKE-03 Go X25519 boundary')
        outcomes[language] = counts
    return outcomes


if __name__ == '__main__':
    print(check())
