#!/usr/bin/env python3
"""Observe EVIDENCE-01 reporting decisions against pinned source."""

import json
import sys

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_evidence_review import IDS, TRACKS, evaluate


def observe(raw, root=ROOT):
    request = load(raw)
    manifest, _, _ = catalog(root)
    source = root / 'verification/0.10.0/current-spec/sources/charter.md'
    content = source.read_bytes()
    require(sha(content) == manifest['source_sha256']['charter.md'] and
            b'EVIDENCE-01' in content, 'pinned evidence source')
    require(type(request) is dict and
            set(request) == {'schema_version', 'spec_revision', 'id',
                             'track', 'input'} and
            request['schema_version'] == 1 and
            request['spec_revision'] == manifest['spec_revision'] and
            request['id'] in IDS and request['track'] in TRACKS,
            'evidence case identity')
    inp = request['input']
    require(type(inp) is dict and set(inp) == {'operation', 'report'} and
            inp['operation'] == 'sage.evidence.review',
            'evidence review operation')
    actual = evaluate(request['id'], request['track'], inp['report'],
                      manifest['spec_revision'])
    return {'schema_version': 1, 'id': request['id'],
            'track': request['track'], 'actual': actual}


def main():
    try:
        raw = sys.stdin.buffer.read(16 * 1024 + 1)
        require(len(raw) <= 16 * 1024, 'evidence case exceeds 16 KiB')
        print(json.dumps(observe(raw), separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError,
            json.JSONDecodeError) as error:
        print('Current spec evidence review FAIL: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
