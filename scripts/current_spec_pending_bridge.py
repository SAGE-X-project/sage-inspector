#!/usr/bin/env python3
"""Classify an explicit host trace against a pinned partial case contract."""

import json
import os
from pathlib import Path
import subprocess
import sys

from current_spec_catalog import ROOT, catalog, load, require
from current_spec_pending_contracts import case_input, inspect


def host_trace(request):
    path = os.environ.get('SAGE_CASE_ADAPTER')
    if not path:
        return None
    adapter = Path(path)
    require(adapter.is_file() and not adapter.is_symlink(),
            'explicit host adapter path')
    raw = json.dumps(request, sort_keys=True, separators=(',', ':')).encode()
    process = subprocess.run([str(adapter)], input=raw, capture_output=True,
                             timeout=10, check=False)
    require(process.returncode == 0 and len(process.stdout) <= 1024 * 1024
            and len(process.stderr) <= 1024 * 1024,
            'host adapter failed or exceeded output bound')
    value = load(process.stdout)
    require(type(value) is dict and set(value) == {'trace'},
            'host adapter trace envelope')
    return value['trace']


def observe(raw, trace_value=None, root=ROOT):
    request = load(raw)
    manifest, source, mapped = catalog(root)
    cases = {row['id']: row for row in source['cases']}
    children = {row['id']: row for row in source['mandatory_subscenarios']}
    rules = {row['id']: row for row in source['rules']}
    require(type(request) is dict and
            set(request) == {'schema_version', 'spec_revision', 'id',
                             'track', 'input'} and
            request['schema_version'] == 1 and
            request['spec_revision'] == manifest['spec_revision'],
            'pending case revision')
    ident, track = request['id'], request['track']
    require(type(ident) is str and type(track) is str and
            (ident in cases or ident in children), 'pending case identity')
    case = cases.get(ident, children.get(ident))
    phase = request['input'].get('phase') if type(request['input']) is dict else None
    rule = rules[case['rule_id']] if ident in cases else rules['MOWN-06']
    suite = load((root / f'vectors/0.10.0/current-spec-phase-{phase}-contracts.json').read_bytes()) \
        if phase in (4, 5, 6) else None
    require(phase in (4, 5, 6) and
            suite['spec_revision'] == manifest['spec_revision'] and
            any(row['id'] == ident and row['track'] == track
                for row in suite['cases']) and
            (track in mapped[ident]['verification_tracks'] if ident in cases
             else track == 'runtime' and phase == 5) and
            request['input'] == case_input(case, rule, track, phase),
            'pending case input and rule provenance')
    if ident == 'REG-08-N04':
        actual = {'verdict': 'UNSUPPORTED',
                  'reason': 'pinned REG-08 does not specify a media-type decision'}
        return {'schema_version': 1, 'id': ident, 'track': track,
                'actual': actual}
    if trace_value is None:
        trace_value = host_trace(request)
    if trace_value is None:
        actual = {'verdict': 'UNSUPPORTED',
                  'reason': 'explicit subject host adapter unavailable'}
    else:
        actual = inspect(case, rule, track, phase, trace_value)
    return {'schema_version': 1, 'id': ident, 'track': track,
            'actual': actual}


def main():
    try:
        raw = sys.stdin.buffer.read(16 * 1024 + 1)
        require(len(raw) <= 16 * 1024, 'pending case exceeds 16 KiB')
        print(json.dumps(observe(raw), separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError,
            json.JSONDecodeError, subprocess.SubprocessError) as error:
        print('Current spec pending contract FAIL: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
