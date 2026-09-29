"""Require every pinned case and mandatory child to have each required track."""

from current_spec_catalog import ROOT, catalog, require
from current_spec_evidence import load_bindings


def check(root=ROOT):
    manifest, trace, mapped = catalog(root)
    children = {row['id']: row for row in trace['mandatory_subscenarios']}
    bindings = load_bindings(root, manifest['spec_revision'], mapped, children)
    required = {(case['id'], track) for case in trace['cases']
                for track in mapped[case['id']]['verification_tracks']}
    required |= {(ident, 'runtime') for ident in children}
    require(set(bindings) == required and len(trace['cases']) == 481 and
            len(children) == 26 and len(bindings) == 554,
            'current spec case-track coverage or mandatory child gap')
    require(all(row['coverage'] == 'partial' for row, _ in bindings.values()),
            'partial contracts cannot be promoted without full evidence')
    return {'parent_cases': len(trace['cases']),
            'mandatory_children': len(children), 'required_tracks': len(required),
            'complete_bindings': 0}


if __name__ == '__main__':
    print(check())
