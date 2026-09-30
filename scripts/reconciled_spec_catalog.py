"""Pin the current 489-case design without transferring historical verdicts."""

import argparse
import json
from pathlib import Path
import subprocess

from current_spec_catalog import (ROOT, catalog, index, load, rendered_snapshot,
                                  require, sha)
from latest_spec_catalog import LATEST_BASE, LATEST_REVISION


BASE = 'verification/0.10.0/reconciled-spec'
REVISION = 'dcdd028b5160de5e32eb1f43cf1f71eed3fc4744'
REGISTRY_SOURCE = 'spec/09-registry.md'
REGISTRY_SHA256 = '828ce810f851c42ab8da76bbc5cfa1cc61fa523ce197b9f784f4aba0a0b345a9'


def rendered(spec_root):
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=spec_root,
                                    text=True, timeout=10).strip() == REVISION,
            'reconciled spec revision')
    previous, previous_trace, previous_map = catalog(base_relative=LATEST_BASE)
    files = rendered_snapshot(spec_root)
    manifest = load(files['manifest.json'])
    require(previous['spec_revision'] == LATEST_REVISION and
            manifest['spec_revision'] == REVISION and
            manifest['counts'] == previous['counts'] and
            files['traceability.json'] ==
            (ROOT / LATEST_BASE / 'traceability.json').read_bytes() and
            files['additional-case-map.json'] ==
            (ROOT / LATEST_BASE / 'additional-case-map.json').read_bytes() and
            len(previous_map) == 489 and len(previous_trace['mandatory_subscenarios']) == 26,
            'case graph differs from preserved 489-case snapshot')
    changed = {name for name, digest in manifest['source_sha256'].items()
               if previous['source_sha256'].get(name) != digest}
    require(changed == {REGISTRY_SOURCE} and
            manifest['source_sha256'][REGISTRY_SOURCE] == REGISTRY_SHA256,
            'unexpected normative source change')
    return files


def assess(root=ROOT, spec_root=None):
    old, old_trace, _ = catalog(root, base_relative=LATEST_BASE)
    current, trace, mapped = catalog(root, spec_root,
                                      base_relative=BASE)
    require(old['spec_revision'] == LATEST_REVISION and
            current['spec_revision'] == REVISION and
            current['counts'] == old['counts'] and
            (root / BASE / 'traceability.json').read_bytes() ==
            (root / LATEST_BASE / 'traceability.json').read_bytes() and
            (root / BASE / 'additional-case-map.json').read_bytes() ==
            (root / LATEST_BASE / 'additional-case-map.json').read_bytes() and
            set(current['source_sha256']) == set(old['source_sha256']) and
            {name for name, digest in current['source_sha256'].items()
             if old['source_sha256'][name] != digest} == {REGISTRY_SOURCE} and
            current['source_sha256'][REGISTRY_SOURCE] == REGISTRY_SHA256,
            'reconciled source delta')
    cases = index(trace['cases'], 'reconciled case')
    require(len(cases) == 489 and len(trace['mandatory_subscenarios']) == 26 and
            len(old_trace['cases']) == 489 and
            mapped['REG-08-N04']['evidence_status'] == 'NOT_RUN',
            'reconciled case inventory')
    return {
        'schema_version': 1, 'kind': 'reconciled-spec-inventory',
        'protocol_version': '0.10.0', 'spec_revision': REVISION,
        'previous_revision': LATEST_REVISION,
        'traceability_sha256': sha((root / BASE / 'traceability.json').read_bytes()),
        'status': 'INVENTORY_ONLY', 'conformance': 'NOT_ESTABLISHED',
        'counts': {'requirements': 45, 'rules': 91, 'cases': 489,
                   'mandatory_subscenarios': 26, 'case_not_run': 489,
                   'mandatory_subscenario_not_run': 26},
        'cases': [{'id': case['id'], 'rule_id': case['rule_id'],
                   'verification_tracks': mapped[case['id']]['verification_tracks'],
                   'status': 'NOT_RUN'} for case in trace['cases']],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        if args.write:
            require(args.spec_root is not None, '--write requires --spec-root')
            for name, raw in rendered(args.spec_root).items():
                path = ROOT / BASE / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
        report = assess(spec_root=args.spec_root)
        if args.report is not None:
            args.report.write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Reconciled spec catalog FAIL: ' + str(error) + '\n')
    print('Reconciled spec inventory: 489 cases NOT_RUN; conformance NOT_ESTABLISHED')


if __name__ == '__main__':
    main()
