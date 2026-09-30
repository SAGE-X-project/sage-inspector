"""Check the bounded REG-08 media decision for the reconciled spec revision."""

import argparse
import json
from pathlib import Path
import re
import subprocess

from current_spec_catalog import ROOT, load, require, sha
from reconciled_spec_catalog import BASE, REGISTRY_SHA256, REVISION, assess


VECTOR = 'vectors/0.10.0/reconciled-spec/reg08-media.json'
VECTOR_SHA256 = '78a0f621e283cb9e17e66cc290dd8b9bda7fa55aa395a285f7c869922ad0dda9'
EXPECTED = {
    'lowercase-json': ('REG-08-P', 'MEDIA_ACCEPT'),
    'mixed-case-json': ('REG-08-P', 'MEDIA_ACCEPT'),
    'wrong-type': ('REG-08-N04', 'RECORD_INVALID'),
    'did-document-type': ('REG-08-N04', 'RECORD_INVALID'),
    'problem-detail-type': ('REG-08-N04', 'RECORD_INVALID'),
    'missing-type': ('REG-08-N04', 'RECORD_INVALID'),
    'parameterized-json': ('REG-08-N04', 'RECORD_INVALID'),
    'duplicate-type': ('REG-08-N04', 'RECORD_INVALID'),
    'combined-type': ('REG-08-N04', 'RECORD_INVALID'),
    'gzip-coding': ('REG-08-N04', 'RECORD_INVALID'),
    'explicit-identity-coding': ('REG-08-N04', 'RECORD_INVALID'),
    'trailer-type': ('REG-08-N04', 'RECORD_INVALID'),
    'trailer-coding': ('REG-08-N04', 'RECORD_INVALID'),
}


def decision(row):
    """A local header-only oracle; it neither fetches nor validates a record."""
    header = row.get('header_lines')
    trailer = row.get('trailer_lines', [])
    require(type(header) is list and type(trailer) is list and
            all(type(line) is list and len(line) == 2 and
                all(type(value) is str for value in line)
                for line in header + trailer), 'media field fixture')
    if any(name.lower() in ('content-type', 'content-encoding')
           for name, _ in trailer):
        return 'RECORD_INVALID'
    if any(name.lower() == 'content-encoding' for name, _ in header):
        return 'RECORD_INVALID'
    values = [value for name, value in header if name.lower() == 'content-type']
    if len(values) != 1:
        return 'RECORD_INVALID'
    # HTTP field OWS may surround a field value. Parameters, lists and suffixes
    # still fail the exact SAGE application/json profile.
    if not re.fullmatch(r'application/json', values[0].strip(' \t'), re.I):
        return 'RECORD_INVALID'
    return 'MEDIA_ACCEPT'


def check(root=ROOT, spec_root=None):
    report = assess(root, spec_root)
    raw = (root / VECTOR).read_bytes()
    require(sha(raw) == VECTOR_SHA256, 'REG-08 media fixture changed')
    suite = load(raw)
    require(set(suite) == {'schema_version', 'kind', 'protocol_version',
                           'rule_id', 'scope', 'cases'} and
            suite['schema_version'] == 1 and
            suite['kind'] == 'web-registry-media-subcondition-vectors' and
            suite['protocol_version'] == '0.10.0' and
            suite['rule_id'] == 'REG-08' and
            len(suite['cases']) == len(EXPECTED), 'media suite identity')
    seen = set()
    for row in suite['cases']:
        ident = row['id']
        require(ident in EXPECTED and ident not in seen and
                (row['parent_case_id'], row['expected']) == EXPECTED[ident] and
                decision(row) == row['expected'], 'media case: ' + ident)
        seen.add(ident)
    parents = {case['id']: case for case in report['cases']
               if case['id'] in {'REG-08-P', 'REG-08-N04'}}
    require(seen == set(EXPECTED) and
            set(parents) == {'REG-08-P', 'REG-08-N04'} and
            all(case['rule_id'] == 'REG-08' and case['status'] == 'NOT_RUN'
                for case in parents.values()) and
            all(case['status'] == 'NOT_RUN' for case in report['cases']) and
            report['spec_revision'] == REVISION and
            report['conformance'] == 'NOT_ESTABLISHED',
            'media coverage is not a complete implementation verdict')
    if spec_root is not None:
        require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=spec_root,
                                        text=True, timeout=10).strip() == REVISION and
                sha((spec_root / 'spec/09-registry.md').read_bytes()) == REGISTRY_SHA256 and
                (spec_root / 'verification/vectors/web-registry-media-0.10.0.json').read_bytes()
                == raw, 'REG-08 source and vector identity')
    return {
        'schema_version': 1, 'kind': 'reg08-media-reference-check',
        'spec_revision': REVISION, 'source_sha256': REGISTRY_SHA256,
        'checked_subconditions': len(seen),
        'parent_cases': {'REG-08-P': 'NOT_RUN', 'REG-08-N04': 'NOT_RUN'},
        'core_implementation': 'NOT_RUN', 'web_origin': 'NOT_RUN',
        'conformance': 'NOT_ESTABLISHED',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        result = check(spec_root=args.spec_root)
        if args.report is not None:
            args.report.write_text(json.dumps(result, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, 'REG-08 media check FAIL: ' + str(error) + '\n')
    print('REG-08 media reference: 13 bounded decisions; parent cases NOT_RUN')


if __name__ == '__main__':
    main()
