#!/usr/bin/env python3
"""Review pinned specification process rules with independent negative controls."""

import json
import sys

from current_spec_catalog import ROOT, catalog, load, require, sha
from current_spec_evidence import validate_outcome
from current_spec_process_review import IDS, evaluate
from generate_current_spec_process_vectors import HISTORICAL


def observe(raw, root=ROOT):
    request = load(raw)
    manifest, trace, _ = catalog(root)
    process = root / 'verification/0.10.0/current-spec/sources/PROCESS.md'
    source = process.read_bytes()
    require(sha(source) == manifest['source_sha256']['PROCESS.md'] and
            b'**PROC-01' in source and b'**PROC-02' in source and
            b'**PROC-03' in source,
            'pinned process source')
    require(type(request) is dict and
            set(request) == {'schema_version', 'spec_revision', 'id',
                             'track', 'input'} and
            request['schema_version'] == 1 and
            request['spec_revision'] == manifest['spec_revision'] and
            request['id'] in IDS and request['track'] == 'document_review',
            'process case identity')
    inp = request['input']
    require(type(inp) is dict and set(inp) == {'operation', 'input'} and
            inp['operation'] == 'sage.process.review' and
            type(inp['input']) is dict and
            set(inp['input']) == {'configuration'}, 'process review operation')
    actual = evaluate(request['id'], inp['input']['configuration'],
                      trace, HISTORICAL, manifest['spec_revision'])
    validate_outcome(actual)
    return {'schema_version': 1, 'id': request['id'],
            'track': 'document_review', 'actual': actual}


def main():
    try:
        raw = sys.stdin.buffer.read(16 * 1024 + 1)
        require(len(raw) <= 16 * 1024, 'process case exceeds 16 KiB')
        print(json.dumps(observe(raw), separators=(',', ':')))
    except (ValueError, KeyError, TypeError, OSError,
            json.JSONDecodeError) as error:
        print('Current spec process review FAIL: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
