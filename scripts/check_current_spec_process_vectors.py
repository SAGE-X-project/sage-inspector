"""Audit all nine process-review fixtures against the pinned process source."""

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_evidence import load_bindings
from current_spec_process_review import IDS, evaluate
from generate_current_spec_process_vectors import HISTORICAL


def check(root=ROOT):
    manifest, trace, mapped = catalog(root)
    suite = load((root / 'vectors/0.10.0/process-review.json').read_bytes())
    source = root / 'verification/0.10.0/current-spec/sources/PROCESS.md'
    require(sha(source.read_bytes()) == manifest['source_sha256']['PROCESS.md'] ==
            suite['process_sha256'], 'pinned process source hash')
    require(suite['schema_version'] == 1 and
            suite['spec_revision'] == manifest['spec_revision'] and
            suite['historical_revision'] == HISTORICAL and
            len(suite['cases']) == len(IDS), 'process suite identity')
    bindings = load_bindings(root, manifest['spec_revision'], mapped,
                             {row['id']: row for row in trace['mandatory_subscenarios']})
    require([row['id'] for row in suite['cases']] == list(IDS),
            'process case order')
    for row in suite['cases']:
        ident = row['id']
        expected = evaluate(ident, row['input']['input']['configuration'],
                            trace, HISTORICAL, manifest['spec_revision'])
        require(row['input']['operation'] == 'sage.process.review' and
                row['expected'] == expected and
                bindings[(ident, 'document_review')][1]['expected'] == expected and
                bindings[(ident, 'document_review')][1]['input'] == row['input'] and
                bindings[(ident, 'document_review')][0]['coverage'] == 'partial',
                'process rule and partial binding: ' + ident)
    return len(IDS)


if __name__ == '__main__':
    print(check())
