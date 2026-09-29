#!/usr/bin/env python3
"""Classify declared Guard security claims against their stated basis."""

import argparse
import json
from pathlib import Path
import sys


def inspect(declaration):
    if type(declaration) is not dict or set(declaration) != {
            'claim', 'basis', 'scope'} or type(declaration['claim']) is not str or \
            type(declaration['basis']) is not list or \
            any(type(item) is not str for item in declaration['basis']) or \
            type(declaration['scope']) is not str:
        return ['invalid security claim declaration']
    claim, basis, scope = (declaration['claim'], set(declaration['basis']),
                           declaration['scope'])
    if claim == 'authenticated-execution-intent':
        required = {'valid-signature', 'trusted-authorization-policy',
                    'enforced-dispatch-boundary'}
        return ([] if scope == 'approved-intent-only' and required <= basis
                else ['intent claim exceeds its authorization boundary'])
    if claim == 'semantic-safety':
        return ([] if 'independent-semantic-safety-evidence' in basis and
                scope == 'separately-evaluated-semantics'
                else ['signature does not establish semantic safety'])
    if claim == 'whole-host-integrity':
        return ([] if 'independent-host-attestation' in basis and
                scope == 'attested-host-boundary'
                else ['file hash does not establish whole-host integrity'])
    return ['unclassified security claim']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = args.input.read_bytes()
        if len(raw) > 1024 * 1024:
            raise ValueError('claim description exceeds 1 MiB')
        defects = inspect(json.loads(raw))
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({'schema_version': 1, 'kind': 'declared-claim-review',
                      'verdict': 'REJECT' if defects else 'ACCEPT',
                      'defects': defects,
                      'document_conformance': 'NOT_ESTABLISHED'},
                     separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
