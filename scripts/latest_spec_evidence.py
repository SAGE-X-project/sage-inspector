"""Assess 489 revision-bound cases without importing earlier observations."""

import argparse
import json
from pathlib import Path
import sys

from current_spec_catalog import ROOT, require
from current_spec_evidence import assess as assess_bindings
from latest_spec_case_bindings import BINDINGS, VECTOR_BASE, check
from latest_spec_catalog import LATEST_BASE, LATEST_REVISION, NEW_IDS


def assess(root=ROOT, evidence_root=None):
    check(root)
    report = assess_bindings(root, evidence_root,
                             base_relative=LATEST_BASE,
                             fixture_prefix=VECTOR_BASE + '/',
                             kind='latest-spec-case-evidence')
    require(report['spec_revision'] == LATEST_REVISION and
            len(report['cases']) == 489 and
            report['conformance'] == 'NOT_ESTABLISHED',
            'latest case evidence identity')
    bindings = json.loads((root / BINDINGS).read_bytes())['bindings']
    require({row['id'] for row in bindings} == NEW_IDS and
            all(row['coverage'] == 'partial' for row in bindings),
            'new case partial bindings')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = assess(evidence_root=args.evidence)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        print('Latest spec evidence FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('Latest spec case results: ' + str(report['counts']) +
          '; conformance NOT_ESTABLISHED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
