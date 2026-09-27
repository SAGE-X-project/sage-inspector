"""Map existing Inspector artifacts to current cases without promoting old evidence."""

import argparse
import collections
import json
from pathlib import Path

from current_spec_catalog import ROOT, catalog, index
from current_spec_evidence import load_bindings


MCP_PLAN = ROOT / 'verification/0.10.0/mcp-consolidated-proposal'
REGISTRY_PROOF_CASES = {
    'mllm-kem-alg-valid', 'mllm-kem-alg-case', 'mllm-kem-selection',
    'mllm-pop-exact-bytes', 'mllm-pop-duplicate-field',
    'mllm-kem-signature-reject', 'mllm-kem-type-valid', 'mllm-kem-key-length',
}


def plan_case_ids():
    return {row['id'] for name in ('cases.json', 'addendum-cases.json', 'resolutions.json')
            for row in json.loads((MCP_PLAN / name).read_text())['cases']}


def assess(root=ROOT):
    manifest, trace, mapped = catalog(root)
    cases = index(trace['cases'], 'case')
    historical = index(json.loads((root / 'verification/0.10.0/case-map.json').read_text())['cases'],
                       'historical case')
    children = index(trace['mandatory_subscenarios'], 'mandatory subscenario')
    bindings = load_bindings(root, manifest['spec_revision'], mapped, children)
    mcp = plan_case_ids()
    if len(mcp) != 71 or not mcp <= set(cases) or not REGISTRY_PROOF_CASES <= set(cases):
        raise ValueError('historical evidence candidates no longer match the spec')
    rows = []
    for case in trace['cases']:
        cid = case['id']
        related = []
        if cid in historical:
            candidate = historical[cid]['partial_vector_ids']
            if candidate:
                related.append({'kind': 'historical_primitive_prerequisite',
                                'source': 'verification/0.10.0/case-map.json',
                                'ids': candidate,
                                'limitation': 'Primitive vectors do not execute this complete spec case.'})
            family = 'baseline'
        elif cid in mcp:
            family = 'mcp_binding'
            related.append({'kind': 'prior_revision_core_overlay',
                            'source': 'docs/mcp-binding-evidence.md',
                            'limitation': 'Prior spec revision and selected core assertions; current case must be revalidated.'})
        elif cid in REGISTRY_PROOF_CASES:
            family = 'registry_clarification'
            if cid == 'mllm-pop-exact-bytes':
                related.append({'kind': 'partial_prior_revision_byte_observation',
                                'source': 'docs/registry-proof010.md',
                                'limitation': 'Exact challenge bytes only; registration proof and current case are not established.'})
        else:
            family = 'later_spec_correction'
        rows.append({'id': cid, 'rule_id': case['rule_id'], 'family': family,
                     'mode': case['mode'],
                     'verification_tracks': mapped[cid]['verification_tracks'],
                     'bound_tracks': {track: binding['coverage']
                                      for (bid, track), (binding, _) in bindings.items()
                                      if bid == cid},
                     'related_historical_evidence': related,
                     'current_case_status': 'NOT_RUN',
                     'current_complete_binding': False})
    counts = dict(collections.Counter(row['family'] for row in rows))
    if counts != {'baseline': 386, 'mcp_binding': 71,
                  'registry_clarification': 8, 'later_spec_correction': 16}:
        raise ValueError('unexpected coverage family counts')
    return {'schema_version': 1, 'kind': 'current-spec-evidence-gap',
            'spec_revision': manifest['spec_revision'],
            'status': 'INCOMPLETE', 'conformance': 'NOT_ESTABLISHED',
            'case_counts': counts, 'mandatory_subscenario_count': len(trace['mandatory_subscenarios']),
            'current_complete_bindings': sum(binding['coverage'] == 'complete'
                                             for binding, _ in bindings.values()),
            'current_partial_bindings': sum(binding['coverage'] == 'partial'
                                            for binding, _ in bindings.values()),
            'historical_primitive_candidates': sum(bool(row['related_historical_evidence'])
                                                    for row in rows if row['family'] == 'baseline'),
            'cases': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = assess()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        parser.exit(1, 'Current spec gap analysis FAIL: ' + str(error) + '\n')
    print('Mapped 481 cases: 386 baseline, 71 MCP, 8 registry, 16 later; '
          'no current complete case bindings.')


if __name__ == '__main__':
    main()
