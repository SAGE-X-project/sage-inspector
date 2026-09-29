"""Inventory the 489-case SAGE specification without inheriting old verdicts."""

import argparse
import json
from pathlib import Path
import subprocess

from current_spec_catalog import ROOT, catalog, index, require, sha


LATEST_BASE = 'verification/0.10.0/latest-spec'
OLD_REVISION = '5bcf511e604579afa63f434013447f44b6858828'
LATEST_REVISION = '44df132fee5925182018ce089dc82435cb353f8a'
NEW_IDS = {
    'msca-http-ed25519', 'msca-http-p256', 'msca-http-private-alg',
    'msca-http-only-private-key', 'msca-http-no-substitution',
    'msca-did-prefix-case', 'msca-did-url-prefix-case',
    'msca-private-suite-non-http-scope',
}


def assess(root=ROOT, spec_root=None):
    previous, old_trace, old_map = catalog(root)
    latest, trace, mapped = catalog(root, spec_root, base_relative=LATEST_BASE)
    old = index(old_trace['cases'], 'previous case')
    current = index(trace['cases'], 'latest case')
    require(previous['spec_revision'] == OLD_REVISION and
            latest['spec_revision'] == LATEST_REVISION and
            previous['counts'] == {
                'requirements': 45, 'rules': 91, 'cases': 481,
                'mandatory_subscenarios': 26, 'historical_cases': 386,
                'additional_cases': 95,
            } and
            latest['counts'] == {
                'requirements': 45, 'rules': 91, 'cases': 489,
                'mandatory_subscenarios': 26, 'historical_cases': 386,
                'additional_cases': 103,
            } and
            len(old_map) == 481 and len(mapped) == 489 and
            set(current) - set(old) == NEW_IDS and
            not set(old) - set(current),
            'spec revision, count or case delta')
    added = [case['id'] for case in trace['cases'] if case['id'] in NEW_IDS]
    report = {
        'schema_version': 1,
        'kind': 'latest-spec-inventory',
        'protocol_version': '0.10.0',
        'spec_revision': LATEST_REVISION,
        'previous_revision': OLD_REVISION,
        'traceability_sha256': sha((root / LATEST_BASE / 'traceability.json').read_bytes()),
        'status': 'INVENTORY_ONLY',
        'conformance': 'NOT_ESTABLISHED',
        'counts': {
            'requirements': 45,
            'rules': 91,
            'cases': 489,
            'mandatory_subscenarios': 26,
            'added_cases': 8,
            'case_not_run': 489,
            'mandatory_subscenario_not_run': 26,
        },
        'added_case_ids': added,
        'cases': [{
            'id': case['id'],
            'rule_id': case['rule_id'],
            'verification_tracks': mapped[case['id']]['verification_tracks'],
            'status': 'NOT_RUN',
            'previous_revision_presence': case['id'] in old,
            'mandatory_subscenarios': [child['id'] for child in trace['mandatory_subscenarios']
                                       if child['parent_case'] == case['id']],
        } for case in trace['cases']],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        report = assess(spec_root=args.spec_root)
        if args.report is not None:
            args.report.write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        parser.exit(1, 'Latest spec catalog FAIL: ' + str(error) + '\n')
    print('Latest spec inventory: 489 cases, 8 added, all NOT_RUN; conformance NOT_ESTABLISHED')


if __name__ == '__main__':
    main()
