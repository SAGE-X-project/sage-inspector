"""Verify preserved process-review observations and their limited scope."""

from check_current_spec_process_vectors import check as check_vectors
from current_spec_catalog import ROOT, load, require, sha
from current_spec_evidence import assess, same
from current_spec_process_review import IDS


BASE = ROOT / 'docs/evidence/current-spec/process-review'


def check(base=BASE, root=ROOT):
    require(check_vectors(root) == 9, 'process fixtures')
    manifest = load((base / 'manifest.json').read_bytes())
    require(manifest['subject']['repository'] == 'SAGE-X-project/sage-spec' and
            manifest['subject']['revision'] == manifest['spec_revision'] and
            len(manifest['observations']) == 9 and
            [row['id'] for row in manifest['observations']] == sorted(IDS),
            'process review source and case identity')
    require(sha((base / 'runner/run_current_spec_cases.py').read_bytes()) ==
            manifest['runner_sha256'] and
            sha((base / 'runner/current_spec_process_bridge.py').read_bytes()) ==
            manifest['adapter_sha256'] == manifest['subject']['executable_sha256'],
            'preserved process reviewer hashes')
    report = assess(root, base)
    require(same(report, load((base / 'assessed.json').read_bytes())) and
            report['counts'] == {'PASS': 0, 'FAIL': 0, 'UNSUPPORTED': 0,
                                 'PARTIAL': 9, 'NOT_RUN': 472} and
            report['conformance'] == 'NOT_ESTABLISHED',
            'process review status')
    rows = {row['id']: row for row in report['cases']}
    require(all(rows[ident]['tracks']['document_review'] == 'PARTIAL'
                for ident in IDS), 'process review track')
    return len(IDS)


if __name__ == '__main__':
    print(check())
