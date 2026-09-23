"""Validate the Rust review against adopted mandatory MCP child schedules."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'verification/0.10.0/rust-normative-review-contract.json'
BASELINE = ROOT / 'verification/0.10.0/normative-baseline-lock.json'
STATUSES = {'DIRECT', 'PARTIAL', 'MISSING'}


def require(value, message):
    if not value:
        raise ValueError(message)


def load(raw):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON member')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError('non-finite number')))


def git_head(path):
    return subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=path, text=True, timeout=10).strip()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def test_inventory(rust_root):
    found = {}
    for path in rust_root.rglob('*.rs'):
        text = path.read_text()
        for name in re.findall(r'^\s*fn ([a-z][a-z0-9_]+)\s*\(\s*\)', text, re.M):
            found.setdefault(name, []).append(str(path.relative_to(rust_root)))
    return found


def validate_contract(value):
    require(set(value) == {'schema_version','protocol_version','kind','spec_revision',
                           'rust_revision','review_status','counts','children','conformance'},
            'contract fields')
    require(value['schema_version'] == 1 and value['protocol_version'] == '0.10.0',
            'contract version')
    require(value['kind'] == 'rust-normative-implementation-review', 'contract kind')
    require(value['review_status'] == 'COMPLETE', 'review status regression')
    require(value['conformance'] == 'NOT_ESTABLISHED', 'conformance promotion')
    baseline = load(BASELINE.read_text())
    require(value['spec_revision'] == baseline['spec']['revision'], 'spec revision')
    require(value['rust_revision'] == baseline['cores']['rust']['revision'], 'Rust revision')
    rows = value['children']
    require(type(rows) is list and len(rows) == 26, 'child count')
    require(len({row.get('id') for row in rows}) == 26, 'child identity uniqueness')
    derived = {status:0 for status in STATUSES}
    for row in rows:
        require(set(row) == {'id','status','tests','observation','required'},
                'child fields')
        require(row['status'] in STATUSES, 'child status')
        require(type(row['tests']) is list and len(set(row['tests'])) == len(row['tests']),
                'test list')
        require((row['status'] == 'MISSING') == (not row['tests']),
                'missing evidence classification')
        require(len(row['observation']) >= 40 and len(row['required']) >= 30,
                'review explanation')
        derived[row['status']] += 1
    require(value['counts'] == derived == {'DIRECT':26,'PARTIAL':0,'MISSING':0},
            'review counts')
    return value


def validate_spec(value, spec_root, revision_reader=git_head):
    require(revision_reader(spec_root) == value['spec_revision'], 'checked spec revision')
    trace = load((spec_root / 'verification/traceability.json').read_text())
    require(trace['binding_adoption']['status'] == 'ADOPTED_NORMATIVE_DESIGN',
            'binding adoption status')
    require(trace['binding_adoption']['parent_cases'] == 71 and
            trace['binding_adoption']['mandatory_child_assertions'] == 26,
            'binding adoption counts')
    expected = {row['id'] for row in trace['mandatory_subscenarios']}
    actual = {row['id'] for row in value['children']}
    require(actual == expected, 'mandatory child inventory')
    return trace


def validate_rust(value, rust_root, revision_reader=git_head):
    require(revision_reader(rust_root) == value['rust_revision'], 'checked Rust revision')
    inventory = test_inventory(rust_root)
    for row in value['children']:
        for name in row['tests']:
            require(name.rsplit('::', 1)[-1] in inventory,
                    'missing Rust test definition: ' + name)
    return inventory


def inspect(spec_root, rust_root):
    raw = CONTRACT.read_bytes()
    value = validate_contract(load(raw.decode()))
    validate_spec(value, spec_root)
    inventory = validate_rust(value, rust_root)
    return {
        'schema_version': 1,
        'protocol_version': '0.10.0',
        'kind': 'rust-normative-implementation-review-report',
        'status': value['review_status'],
        'spec_revision': value['spec_revision'],
        'rust_revision': value['rust_revision'],
        'counts': value['counts'],
        'mapped_rust_tests': len({name for row in value['children'] for name in row['tests']}),
        'discovered_rust_tests': len(inventory),
        'next_step': 'bind both completed core reviews to Inspector execution evidence',
        'conformance': 'NOT_ESTABLISHED',
        'contract_sha256': sha(raw)
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-root', type=Path, required=True)
    parser.add_argument('--rust-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        require(not output.exists() and not output.is_relative_to(ROOT),
                'new external output required')
        report = inspect(args.spec_root.resolve(), args.rust_root.resolve())
        output.mkdir(parents=True, exist_ok=False)
        (output / 'contract.json').write_bytes(CONTRACT.read_bytes())
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    except (ValueError, KeyError, TypeError, OSError, UnicodeError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        print('Rust normative review FAIL: ' + str(error), file=sys.stderr)
        return 1
    print('Rust normative review checked: 26 DIRECT, 0 PARTIAL, 0 MISSING; '
          'conformance NOT_ESTABLISHED.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
