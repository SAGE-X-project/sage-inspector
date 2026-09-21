"""Check canonical Guard evidence consistency, not artifact authenticity or conformance."""
import argparse
import json
from pathlib import Path
import re
from check_guard_signature_boundaries import CANONICAL_SHA, audit, fixtures, sha, validate_response
from inspect_guard_binding import load, require
from test_record010_adapters import PINS


def same(actual, expected, label):
    # JSON type identity matters: Python considers True == 1.
    require(json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True), label)


def verify(directory, revision, executable_hashes, checked):
    require(re.fullmatch(r'[0-9a-f]{40}', revision) is not None, 'expected revision')
    rows = fixtures(True)
    names = {'report.json'}
    for subject in PINS:
        for case in rows:
            names.update(subject+'-'+case['id']+suffix for suffix in ('.request.json', '.stdout', '.stderr'))
    require({p.name for p in directory.iterdir()} == names, 'artifact file membership')
    require(all((directory/name).is_file() and not (directory/name).is_symlink() for name in names), 'regular artifact files required')
    report = load((directory/'report.json').read_bytes())
    expected = dict(kind='guard-signature-boundaries', status='PASS', actual_core_execution=True,
                    conformance='NOT_ESTABLISHED', mcp_protocol_execution='NOT_RUN',
                    proposal_cases={'NOT_RUN':71}, lifecycle={'NOT_RUN':37},
                    fixture_sha256=CANONICAL_SHA, suite='canonical-signatures',
                    inspector_revision=revision, signature_audit=checked,
                    audit_executable_sha256=executable_hashes['audit'])
    for key, value in expected.items():
        same(report[key], value, 'report '+key)
    same(set(report['subjects']) == set(PINS), True, 'subject membership')
    require(type(report['limitations']) is list and len(report['limitations']) >= 4 and
            all(type(v) is str and v for v in report['limitations']), 'scope limitations')
    observed = []
    for subject, pin in PINS.items():
        same(report['subjects'][subject], dict(revision=pin, adapter_sha256=executable_hashes[subject]), 'subject identity')
        for case in rows:
            stem = subject+'-'+case['id']
            request = load((directory/(stem+'.request.json')).read_bytes())
            same(request, dict(schema_version=1, protocol_version='0.10.0', profile='primitive-foundation',
                 case_id=case['id'], operation=case['operation'], input=case['input']), 'request mismatch: '+stem)
            raw = (directory/(stem+'.stdout')).read_bytes()
            validate_response(case, load(raw))
            require((directory/(stem+'.stderr')).read_bytes() == b'', 'unexpected stderr: '+stem)
            observed.append(dict(subject=subject, id=case['id'], status='PASS', verdict=case['expected'], response_sha256=sha(raw)))
    same(report['results'], observed, 'result membership, order or digest')
    return len(observed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--revision', required=True)
    for name in ('go', 'rust', 'audit'):
        parser.add_argument('--'+name, required=True, type=Path)
    args = parser.parse_args()
    # These executables must come from a trusted build, never from the artifact.
    hashes = {name:sha(getattr(args, name).read_bytes()) for name in ('go', 'rust', 'audit')}
    count = verify(args.evidence, args.revision, hashes, audit(True, args.audit.resolve()))
    print(f'PASS: {count} canonical Guard exchanges; evidence consistency only; MCP remains NOT_RUN')


if __name__ == '__main__':
    main()
