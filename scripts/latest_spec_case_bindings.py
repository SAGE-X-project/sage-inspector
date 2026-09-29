"""Pin the eight new cases to source-exact, partial host observation contracts."""

import argparse
import json
from pathlib import Path
import subprocess

from current_spec_catalog import ROOT, catalog, index, require, sha
from latest_spec_catalog import LATEST_BASE, LATEST_REVISION, NEW_IDS


VECTOR_BASE = 'vectors/0.10.0/latest-spec'
BINDINGS = LATEST_BASE + '/bindings.json'


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()


def rendered(root=ROOT, spec_root=None):
    manifest, trace, mapped = catalog(root, spec_root, base_relative=LATEST_BASE)
    require(manifest['spec_revision'] == LATEST_REVISION, 'latest binding revision')
    cases = index(trace['cases'], 'latest case')
    rules = index(trace['rules'], 'latest rule')
    require(NEW_IDS <= set(cases), 'missing new cases')
    files = {}
    bindings = []
    for case in trace['cases']:
        ident = case['id']
        if ident not in NEW_IDS:
            continue
        require(case['mode'] == 'unit_and_bounded_local_runtime' and
                mapped[ident]['verification_tracks'] == ['runtime'] and
                not any(child['parent_case'] == ident
                        for child in trace['mandatory_subscenarios']),
                'new case verification mode: ' + ident)
        rule = rules[case['rule_id']]
        fixture = {
            'schema_version': 1,
            'spec_revision': LATEST_REVISION,
            'id': ident,
            'track': 'runtime',
            'input': {
                'operation': 'sage.spec.host_case',
                'id': ident,
                'track': 'runtime',
                'rule_id': case['rule_id'],
                'source': rule['source'],
                'source_line': rule['line'],
                'source_case_sha256': sha(encode(case)),
                'trigger': case['input'],
                'preconditions': case['preconditions'],
                'normative_expected': case['expected'],
            },
            'expected': {'verdict': 'ACCEPT',
                         'output': {'matched': True, 'reason': 'case_contract'},
                         'effects': {}},
        }
        path = f'{VECTOR_BASE}/{ident}.json'
        raw = encode(fixture)
        files[path] = raw
        bindings.append({'id': ident, 'track': 'runtime', 'fixture': path,
                         'fixture_sha256': sha(raw), 'coverage': 'partial'})
    require(len(bindings) == 8, 'new case binding count')
    files[BINDINGS] = encode({'schema_version': 1,
                              'spec_revision': LATEST_REVISION,
                              'bindings': bindings})
    return files


def check(root=ROOT, spec_root=None):
    files = rendered(root, spec_root)
    for relative, expected in files.items():
        require((root / relative).read_bytes() == expected,
                'latest case binding differs: ' + relative)
    return {'cases': 8, 'coverage': 'partial',
            'implementation_conformance': 'NOT_ESTABLISHED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    try:
        if args.write:
            for relative, raw in rendered(spec_root=args.spec_root).items():
                path = ROOT / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
        result = check(spec_root=args.spec_root)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Latest spec bindings FAIL: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
