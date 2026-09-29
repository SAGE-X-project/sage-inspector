"""Audit nine EVIDENCE-01 tracks and their preserved partial observations."""

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_evidence import assess, load_bindings, same
from current_spec_evidence_review import IDS, TRACKS, evaluate
from generate_current_spec_evidence_vectors import cases


BASE = ROOT / 'docs/evidence/current-spec/evidence-review'


def check(root=ROOT, base=BASE):
    manifest, trace, mapped = catalog(root)
    suite = load((root / 'vectors/0.10.0/evidence-review.json').read_bytes())
    source = root / 'verification/0.10.0/current-spec/sources/charter.md'
    require(sha(source.read_bytes()) == suite['source_sha256'] ==
            manifest['source_sha256']['charter.md'], 'pinned evidence source')
    require(suite['spec_revision'] == manifest['spec_revision'] and
            len(suite['cases']) == len(IDS) * len(TRACKS), 'evidence suite')
    bindings = load_bindings(root, manifest['spec_revision'], mapped,
                             {row['id']: row for row in trace['mandatory_subscenarios']})
    for row, (ident, track, inp, expected) in zip(suite['cases'], cases()):
        require(row == {'id': ident, 'track': track, 'input': inp,
                        'expected': expected} and
                track in mapped[ident]['verification_tracks'] and
                bindings[(ident, track)][0]['coverage'] == 'partial' and
                bindings[(ident, track)][1]['expected'] == expected and
                evaluate(ident, track, inp['report'],
                         manifest['spec_revision']) == expected,
                'evidence partial fixture')
    observed = load((base / 'manifest.json').read_bytes())
    require(len(observed['observations']) == 9 and
            {(row['id'], row['track']) for row in observed['observations']} ==
            {(ident, track) for ident in IDS for track in TRACKS} and
            observed['subject']['repository'] == 'SAGE-X-project/sage-spec' and
            observed['subject']['revision'] == manifest['spec_revision'] and
            sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
            observed['runner_sha256'] and
            sha((base / 'runner/current_spec_evidence_bridge.py').read_bytes()) ==
            observed['adapter_sha256'], 'evidence observation provenance')
    report = assess(root, base)
    require(same(report, load((base / 'assessed.json').read_bytes())) and
            report['counts'] == {'PASS': 0, 'FAIL': 0, 'UNSUPPORTED': 0,
                                 'PARTIAL': 3, 'NOT_RUN': 478} and
            report['conformance'] == 'NOT_ESTABLISHED',
            'evidence results cannot prove implementation')
    return 9


if __name__ == '__main__':
    print(check())
